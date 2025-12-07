#!/usr/bin/env python3
"""
Prepare Commit Fuzzer
Gets changed functions from a commit and finds tests that cover those functions.
Prepares a matrix for fuzzing jobs.
"""

import json
import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional
import argparse
import gc
import git
import re
import difflib
import ctypes
from ctypes.util import find_library
from os.path import normpath
from dataclasses import dataclass

import clang.cindex

# Monkey-patch: expose template argument introspection via libclang C API if missing
try:
    libname = find_library('clang')
    if libname:
        _libclang = ctypes.CDLL(libname)

        CXType = clang.cindex.CXType  # type: ignore

        _libclang.clang_Type_getNumTemplateArguments.argtypes = [CXType]
        _libclang.clang_Type_getNumTemplateArguments.restype = ctypes.c_int

        _libclang.clang_Type_getTemplateArgumentAsType.argtypes = [CXType, ctypes.c_uint]
        _libclang.clang_Type_getTemplateArgumentAsType.restype = CXType

        def _get_num_template_arguments(t):
            try:
                return _libclang.clang_Type_getNumTemplateArguments(t._type)
            except Exception:
                return -1

        def _get_template_argument_type(t, idx: int):
            try:
                cxt = _libclang.clang_Type_getTemplateArgumentAsType(t._type, ctypes.c_uint(idx))
                if hasattr(clang.cindex, 'Type') and hasattr(clang.cindex.Type, 'from_result'):
                    return clang.cindex.Type.from_result(cxt)  # type: ignore
                return t
            except Exception:
                return t

        if not hasattr(clang.cindex.Type, 'get_num_template_arguments'):
            clang.cindex.Type.get_num_template_arguments = _get_num_template_arguments  # type: ignore
        if not hasattr(clang.cindex.Type, 'get_template_argument_type'):
            clang.cindex.Type.get_template_argument_type = _get_template_argument_type  # type: ignore
except Exception:
    pass

@dataclass
class FunctionInfo:
    signature: str
    start: int
    end: int
    file: str

class GitHelper:
    def __init__(self, repo_path: Path, repo: git.Repo):
        self.repo_path = repo_path
        self.repo = repo

    def get_commit_info(self, commit_hash: str) -> Optional[Dict]:
        try:
            commit = self.repo.commit(commit_hash)
            return {
                'hash': commit.hexsha,
                'author_name': commit.author.name,
                'author_email': commit.author.email,
                'date': commit.authored_datetime.isoformat(),
                'message': commit.message.strip(),
                'summary': commit.summary
            }
        except Exception as e:
            print(f"Error getting commit info: {e}")
            return None

    def get_commit_diff(self, commit_hash: str) -> str:
        try:
            result = subprocess.run(['git', 'show', '-U0', '--no-color', commit_hash],
                                    capture_output=True, text=True, cwd=self.repo_path)
            return result.stdout
        except Exception as e:
            print(f"Error getting commit diff: {e}")
            return ""

    def get_changed_lines(self, diff_text: str) -> Dict[str, Set[int]]:
        changed_lines: Dict[str, Set[int]] = {}
        current_file: Optional[str] = None
        in_hunk = False
        new_line = None
        for raw in diff_text.split('\n'):
            if raw.startswith('diff --git '):
                current_file = None
                in_hunk = False
                new_line = None
                continue
            if raw.startswith('+++ b/'):
                current_file = raw[6:]
                if current_file not in changed_lines:
                    changed_lines[current_file] = set()
                continue
            if raw.startswith('@@ '):
                m = re.search(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', raw)
                if current_file and m:
                    new_line = int(m.group(1))
                    in_hunk = True
                else:
                    in_hunk = False
                    new_line = None
                continue
            if not in_hunk or current_file is None or new_line is None:
                continue
            if raw.startswith('+') and not raw.startswith('+++'):
                changed_lines[current_file].add(new_line)
                new_line += 1
            elif raw.startswith('-') and not raw.startswith('---'):
                pass
            else:
                new_line += 1
        return changed_lines

    def get_file_text_at_commit(self, rev: Optional[str], path: str) -> Optional[str]:
        if not rev:
            return None
        try:
            result = subprocess.run(['git', 'show', f'{rev}:{path}'], capture_output=True, text=True, cwd=self.repo_path)
            if result.returncode != 0:
                return None
            return result.stdout
        except Exception:
            return None

class Matcher:
    def __init__(self, coverage_map: Dict[str, Set[str]]):
        self.coverage_map = coverage_map

    def _strip_line_suffix(self, s: str) -> str:
        if ':' in s:
            base, last = s.rsplit(':', 1)
            if last.isdigit():
                return base
        return s

    def _split_path_and_sig(self, key: str):
        no_line = self._strip_line_suffix(key)
        if ':' in no_line:
            path, sig = no_line.split(':', 1)
            return path, sig
        return '', no_line


    def match(self, functions: List[str]) -> Dict:
        cov_full_to_tests: Dict[str, Set[str]] = {}
        cov_sig_to_tests: Dict[str, Set[str]] = {}
        # Map normalized signature (without :line) to example full keys for debug
        cov_sig_to_fulls: Dict[str, List[str]] = {}
        for k, tests in self.coverage_map.items():
            path, sig = self._split_path_and_sig(k)
            full = f"{path}:{sig}"
            cov_full_to_tests.setdefault(full, set()).update(tests)
            cov_sig_to_tests.setdefault(sig, set()).update(tests)
            # Store original mapping key (with :line) for debug visibility
            cov_sig_to_fulls.setdefault(sig, []).append(k)
        cov_sigs_list = list(cov_sig_to_tests.keys())

        all_covering_tests = set()
        functions_with_tests = 0
        functions_without_tests = 0
        function_test_counts: Dict[str, int] = {}
        test_function_counts: Dict[str, int] = {}
        direct_matches = 0
        path_removed_matches = 0
        function_matches: Dict[str, Dict] = {}
        match_type_counts: Dict[str, int] = {}

        for func in functions:
            matching_tests = set()
            match_type = "none"
            our_path, our_sig = self._split_path_and_sig(func)
            our_sig_norm = self._strip_line_suffix(our_sig)
            our_full_norm = f"{our_path}:{our_sig_norm}"

            if our_full_norm in cov_full_to_tests:
                tests = cov_full_to_tests[our_full_norm]
                matching_tests.update(tests)
                direct_matches += 1
                match_type = "direct"
            elif our_sig_norm in cov_sig_to_tests:
                tests = cov_sig_to_tests[our_sig_norm]
                matching_tests.update(tests)
                path_removed_matches += 1
                match_type = "path_removed"
                # Debug: show example mapping keys for this signature
                try:
                    examples = cov_sig_to_fulls.get(our_sig_norm, [])
                    if examples:
                        print(f"DEBUG_PATHLESS our={our_sig_norm} examples={examples}")
                except Exception:
                    pass
            else:
                try:
                    best = max(
                        ((cov_sig, difflib.SequenceMatcher(None, our_sig_norm, cov_sig).ratio()) for cov_sig in cov_sigs_list),
                        key=lambda x: x[1],
                        default=(None, 0.0)
                    )
                    best_sig, best_ratio = best
                    if best_sig is not None and best_ratio >= 0.9:
                        # Do NOT count fuzzy matches as coverage; only report candidates
                        match_type = f"fuzzy_candidate:{best_ratio:.2f}"
                        try:
                            examples = cov_sig_to_fulls.get(best_sig, [])
                            if examples:
                                print(f"DEBUG_FUZZY_MAP our={our_sig_norm} matched_sig={best_sig} examples={examples}")
                        except Exception:
                            pass
                except Exception:
                    pass

            if matching_tests:
                all_covering_tests.update(matching_tests)
                functions_with_tests += 1
                function_test_counts[func] = len(matching_tests)
                for test in matching_tests:
                    test_function_counts[test] = test_function_counts.get(test, 0) + 1
            else:
                functions_without_tests += 1
                function_test_counts[func] = 0

            function_matches[func] = {
                'tests': sorted(list(matching_tests)),
                'match_type': match_type
            }
            match_type_counts[match_type] = match_type_counts.get(match_type, 0) + 1

        return {
            'all_covering_tests': all_covering_tests,
            'functions_with_tests': functions_with_tests,
            'functions_without_tests': functions_without_tests,
            'total_tests': len(all_covering_tests),
            'function_test_counts': function_test_counts,
            'test_function_counts': test_function_counts,
            'direct_matches': direct_matches,
            'path_removed_matches': path_removed_matches,
            'function_matches': function_matches,
            'match_type_counts': match_type_counts
        }

class PrepareCommitAnalyzer:
    def __init__(self, repo_path: str = ".", compile_commands: Optional[str] = None):
        """Initialize with repository path."""
        self.repo_path = Path(repo_path)
        self.repo = git.Repo(repo_path)
        self.coverage_map = None
        self.compdb = None
        self.compdb_dir: Optional[str] = None
        self.git = GitHelper(self.repo_path, self.repo)
        if compile_commands:
            self._init_compilation_database(compile_commands)

    def _init_compilation_database(self, compile_commands: str) -> None:
        try:
            cc_path = Path(compile_commands)
            cc_dir = cc_path if cc_path.is_dir() else cc_path.parent
            db = clang.cindex.CompilationDatabase.fromDirectory(str(cc_dir))  # type: ignore
            # Probe database (may raise if not usable)
            _ = db.getAllCompileCommands()  # type: ignore[attr-defined]
            self.compdb = db
            self.compdb_dir = str(cc_dir)
        except Exception:
            self.compdb = None
            self.compdb_dir = None

    def _extract_args_from_compile_command(self, cmd) -> List[str]:
        args: List[str] = []
        try:
            # libclang API differences: use .arguments if present, else .commandLine
            raw = list(getattr(cmd, 'arguments', None) or getattr(cmd, 'commandLine', []))
            # Drop the compiler binary and the source file path
            # Also drop output-related flags (-o, /Fo, etc.) and compile-only flags like -c
            skip_next = False
            src = str(getattr(cmd, 'filename', ''))
            for i, a in enumerate(raw):
                if skip_next:
                    skip_next = False
                    continue
                if i == 0:
                    continue
                if a == src or a.endswith(src):
                    continue
                if a in ('-c',):
                    continue
                if a in ('-o', '/Fo'):
                    skip_next = True
                    continue
                args.append(a)
        except Exception:
            return []
        # Ensure language for headers
        if '-x' not in args:
            args = ['-x', 'c++'] + args
        return args

    def _get_clang_args_for_file(self, file_path: str) -> List[str]:
        # Try compilation database
        if self.compdb:
            try:
                abs_path = str((self.repo_path / file_path).resolve()) if not os.path.isabs(file_path) else file_path
                cmds = self.compdb.getCompileCommands(abs_path)  # type: ignore
                if cmds and len(cmds) > 0:
                    # Pick first entry
                    cc = cmds[0]
                    args = self._extract_args_from_compile_command(cc)
                    # Add resource dir if available
                    crd = self._clang_resource_dir()
                    if crd and '-resource-dir' not in args:
                        args.extend(['-resource-dir', crd])
                    return args
            except Exception:
                pass
        # Fallback
        return self._build_clang_args()

    def _demangle_with_cxxfilt(self, mangled: Optional[str]) -> Optional[str]:
        """Demangle a mangled C++ symbol using c++filt (binutils)."""
        if not mangled:
            return None
        try:
            res = subprocess.run(['c++filt'], input=str(mangled), capture_output=True, text=True)
            if res.returncode == 0 and res.stdout:
                return res.stdout.strip()
        except Exception:
            pass
        return None
    def get_function_signature(self, cursor) -> Optional[str]:
        """Extract gcov-style function signature from a clang cursor"""
        try:
            # Prefer demangled signature from mangled name (matches coverage mapping formatting)
            line = cursor.location.line
            mangled = getattr(cursor, 'mangled_name', None)
            demangled = self._demangle_with_cxxfilt(mangled)
            if demangled:
                # Use demangled signature as-is with line suffix
                return f"{demangled}:{line}"

            # Fallback to AST-rendered signature
            name = cursor.spelling
            if not name:
                return None

            qualified_name = self.get_qualified_name(cursor)
            params = []
            # Get parameters with template-aware rendering (best effort)
            for child in cursor.get_children():
                if child.kind == clang.cindex.CursorKind.PARM_DECL:
                    params.append(self._render_param_type(child.type))

            param_str = ", ".join(params)
            const_suffix = " const" if cursor.is_const_method() else ""
            
            # Add ABI information if present (like [abi:cxx11])
            abi_info = ""
            if hasattr(cursor, 'mangled_name') and cursor.mangled_name:
                # Check for ABI-specific mangling
                if 'abi:cxx11' in str(cursor.mangled_name):
                    abi_info = "[abi:cxx11]"
            
            line = cursor.location.line
            signature = f"{qualified_name}({param_str}){abi_info}{const_suffix}:{line}"
            # Normalize once to match coverage mapping formatting
            return self._normalize_signature(signature)
        except Exception:
            return None

    def _render_param_type(self, tp) -> str:
        """Render parameter type with template arguments where possible using libclang APIs.
        Falls back to canonical spelling.
        """
        try:
            # Prefer named/elaborated named type for better spelling
            try:
                named = tp.get_named_type()
                if named.spelling:
                    tp = named
            except Exception:
                pass

            # libclang python bindings may expose num_template_arguments
            num_targs = getattr(tp, 'get_num_template_arguments', None)
            get_targ = getattr(tp, 'get_template_argument_type', None)
            if callable(num_targs) and callable(get_targ):
                n = num_targs()
                if isinstance(n, int) and n > 0:
                    # Render base name
                    base = tp.spelling or tp.get_canonical().spelling
                    base = base.split('<', 1)[0].strip()
                    # Collect arguments
                    args: List[str] = []
                    for i in range(n):
                        try:
                            at = get_targ(i)
                            if at and (at.spelling or at.get_canonical().spelling):
                                args.append(self._render_param_type(at))
                        except Exception:
                            pass
                    if args:
                        return f"{base}<{', '.join(args)}>"

            # Prefer fully-qualified canonical for non-templates; fallback to spelling
            can = tp.get_canonical().spelling or ''
            sp = tp.spelling or ''
            # If canonical shows namespaces or templates, prefer it
            if '::' in can or '<' in can:
                s = can
            elif '::' in sp or '<' in sp:
                s = sp
            else:
                # last resort
                s = can or sp
            s = (s or '').replace('  ', ' ').strip()
            return s
        except Exception:
            try:
                return tp.spelling or tp.get_canonical().spelling or ''
            except Exception:
                return ''


    def _clang_resource_dir(self) -> Optional[str]:
        """Try to get clang resource dir for proper builtin headers."""
        try:
            res = subprocess.run(['clang', '-print-resource-dir'], capture_output=True, text=True)
            if res.returncode == 0:
                d = res.stdout.strip()
                if d and os.path.isdir(d):
                    return d
        except Exception:
            pass
        return None

    
    def get_qualified_name(self, cursor) -> str:
        """Get the fully qualified name including namespace and class"""
        parts = []
        current = cursor
        
        while current:
            if current.kind in [clang.cindex.CursorKind.NAMESPACE, 
                              clang.cindex.CursorKind.CLASS_DECL,
                              clang.cindex.CursorKind.STRUCT_DECL,
                              clang.cindex.CursorKind.FUNCTION_DECL,
                              clang.cindex.CursorKind.CXX_METHOD]:
                name = current.spelling
                if name and name not in parts:  # Avoid duplicates
                    parts.append(name)
            current = current.semantic_parent
        
        parts.reverse()
        qualified_name = "::".join(parts)
        
        # Ensure we have the full cvc5:: namespace
        if not qualified_name.startswith('cvc5::'):
            # Try to find the actual namespace context
            if 'cvc5::' in qualified_name:
                # Extract everything from cvc5:: onwards
                cvc5_index = qualified_name.find('cvc5::')
                qualified_name = qualified_name[cvc5_index:]
        
        return qualified_name
    
    def is_cvc5_function(self, signature: str) -> bool:
        """Check if a function signature belongs to cvc5.
        Only consider the qualified function name (before '('), allow std types in parameters.
        """
        try:
            head = signature.split('(')[0]
            # If the function itself is in std or gnu namespaces, skip
            if head.startswith('std::') or head.startswith('__') or head.startswith('__gnu_cxx::'):
                return False
            # Include any functions within the cvc5 namespace
            if 'cvc5::' in head:
                return True
            # Fallback: if it has a namespace and isn't std/gnu, accept
            if '::' in head:
                ns = head.split('::', 1)[0]
                if ns and ns != 'std' and not ns.startswith('__') and ns != '__gnu_cxx':
                    return True
            return False
        except Exception:
            return False
    
    def get_commit_functions(self, commit_hash: str) -> tuple[List[str], List[str]]:
        """Get changed C++ functions by intersecting diff ranges with AST extents.
        Includes functions whose body overlaps changed lines or whose signature changed.
        Excludes pure moves (identical normalized body before/after).
        
        Returns:
            (changed_functions, files_with_no_functions) where:
            - changed_functions: List of function signatures found
            - files_with_no_functions: List of .cpp/.hpp file paths that were changed but had no functions detected
        """
        commit_info = self.git.get_commit_info(commit_hash)
        if not commit_info:
            return ([], [])

        # Get diff and changed line ranges on the new side
        diff_text = self.git.get_commit_diff(commit_hash)
        changed_files_lines = self.git.get_changed_lines(diff_text)

        # Parent commit (if any)
        try:
            commit = self.repo.commit(commit_hash)
            parent_hash = commit.parents[0].hexsha if commit.parents else None
        except Exception:
            parent_hash = None

        changed_functions: List[str] = []
        files_with_no_functions: List[str] = []

        for file_path, changed_lines in changed_files_lines.items():
            # Only consider project sources under src/ and C++ files
            if not (file_path.startswith('src/') and file_path.endswith(('.cpp', '.cc', '.c', '.h', '.hpp'))):
                continue

            after_src = self.git.get_file_text_at_commit(commit_hash, file_path)
            if after_src is None:
                continue
            before_src = self.git.get_file_text_at_commit(parent_hash, file_path) if parent_hash else None

            # Parse functions from in-memory contents
            after_funcs = self.parse_functions_from_text(file_path, after_src)
            before_funcs = self.parse_functions_from_text(file_path, before_src) if before_src is not None else []

            # Build indexes for before
            before_by_sig = {self.build_signature_key(f.signature): f for f in before_funcs}

            # Helper to normalize function body slice
            def normalized_body(src: str, f: FunctionInfo) -> str:
                lines = src.splitlines()
                s = max(1, int(f.start))
                e = min(len(lines), int(f.end))
                snippet = "\n".join(lines[s-1:e])
                return self.normalize_code(snippet)

            # Per changed line: select the innermost enclosing function (smallest extent)
            selected: Dict[str, FunctionInfo] = {}
            if after_funcs:
                cvc5_funcs = [f for f in after_funcs if self.is_cvc5_function(f.signature)]
                for ln in sorted(changed_lines):
                    candidates = [f for f in cvc5_funcs if int(f.start) <= ln <= int(f.end)]
                    if not candidates:
                        continue
                    # choose innermost by minimal extent length, then earliest start
                    chosen = min(candidates, key=lambda f: (int(f.end) - int(f.start), int(f.start)))
                    key = self.build_signature_key(chosen.signature)
                    selected[key] = chosen

            # Check if this is a .cpp or .hpp file with no functions detected
            if file_path.endswith(('.cpp', '.hpp')) and len(selected) == 0:
                files_with_no_functions.append(file_path)

            # Emit selected functions, dropping pure moves
            for sig_key, f in selected.items():
                # Exclude pure move if existed before and bodies equal
                is_move = False
                if before_src is not None and sig_key in before_by_sig:
                    bf = before_by_sig[sig_key]
                    if normalized_body(before_src, bf) == normalized_body(after_src, f):
                        is_move = True
                if is_move:
                    continue
                mapping_entry = f"{file_path}:{f.signature}"
                changed_functions.append(mapping_entry)
                print(f"    Selected: {mapping_entry} (overlap=True, sig_changed=False)")

        return (changed_functions, files_with_no_functions)

    def parse_functions_from_text(self, file_path: str, source_text: Optional[str]) -> List[FunctionInfo]:
        """Parse C++ function definitions from provided source text using libclang unsaved_files."""
        if source_text is None:
            return []
        
        try:
            index = clang.cindex.Index.create()
            args = self._get_clang_args_for_file(file_path)
            abs_path = str((self.repo_path / file_path).resolve()) if not os.path.isabs(file_path) else file_path
            tu = index.parse(abs_path, args=args, unsaved_files=[(abs_path, source_text)])
            try:
                if tu.diagnostics:
                    print(f"DEBUG_CLANG_TU_DIAG_COUNT: {len(tu.diagnostics)}")
                    for diag in tu.diagnostics:
                        print(f"DEBUG_CLANG_TU_DIAG: {diag.severity}: {diag.spelling}")
            except Exception:
                pass

            funcs: List[FunctionInfo] = []

            def visit(n):
                if n.kind in [clang.cindex.CursorKind.FUNCTION_DECL, clang.cindex.CursorKind.CXX_METHOD] and n.is_definition():
                    sig = self.get_function_signature(n)
                    node_file = str(n.location.file) if n.location and n.location.file else None
                    if sig and node_file and self.is_cvc5_function(sig):
                        nf = normpath(node_file)
                        exp = normpath(abs_path)
                        if nf.endswith(exp):
                            funcs.append(FunctionInfo(
                                signature=sig,
                                start=n.extent.start.line,
                                end=n.extent.end.line,
                                file=node_file
                            ))
                for c in n.get_children():
                    visit(c)

            visit(tu.cursor)
            return funcs
        except Exception:
            return []

    def build_signature_key(self, signature: str) -> str:
        """Normalize a signature to a stable key (drop ':line')."""
        if ':' in signature:
            base, last = signature.rsplit(':', 1)
            if last.isdigit():
                return base
        return signature

    def normalize_code(self, code: str) -> str:
        """Remove comments and collapse whitespace for rough body comparison."""
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
        code = re.sub(r'\s+', ' ', code).strip()
        return code

    def _normalize_signature(self, full_sig: str) -> str:
        """Normalize a constructed signature string to match coverage mapping style, once.
        Preserves trailing :line while normalizing whitespace, namespaces, template spacing,
        and parameter const placement.
        """
        try:
            # Split off :line suffix if present
            line_part = ''
            head = full_sig
            if ':' in full_sig:
                base, last = full_sig.rsplit(':', 1)
                if last.isdigit():
                    head = base
                    line_part = f":{last}"

            # Remove ABI tag
            head = re.sub(r"\[abi:[^\]]+\]", "", head)
            # Collapse namespace spacing
            head = re.sub(r"\s*::\s*", "::", head)

            # Find parameter list boundaries on the head (no :line now)
            s = head
            open_idx = -1
            angle = 0
            for i, ch in enumerate(s):
                if ch == '<':
                    angle += 1
                elif ch == '>':
                    angle = max(0, angle - 1)
                elif ch == '(' and angle == 0:
                    open_idx = i
                    break
            if open_idx == -1:
                # No params? Just collapse spaces and template closers
                s = re.sub(r"\s+", " ", s)
                s = s.replace(">>", "> >")
                return s.strip() + line_part

            paren = 0
            close_idx = -1
            for j in range(open_idx, len(s)):
                c = s[j]
                if c == '<':
                    angle += 1
                elif c == '>':
                    angle = max(0, angle - 1)
                elif c == '(':
                    paren += 1
                elif c == ')':
                    paren -= 1
                    if paren == 0 and angle == 0:
                        close_idx = j
                        break
            if close_idx == -1:
                s = re.sub(r"\s+", " ", s)
                s = s.replace(">>", "> >")
                return s.strip() + line_part

            prefix = s[:open_idx+1]
            params_str = s[open_idx+1:close_idx]
            suffix = s[close_idx:]

            # Split top-level parameters
            params: List[str] = []
            buf: List[str] = []
            angle = 0
            paren = 0
            for ch in params_str:
                if ch == '<':
                    angle += 1
                elif ch == '>':
                    angle = max(0, angle - 1)
                elif ch == '(':
                    paren += 1
                elif ch == ')':
                    paren = max(0, paren - 1)
                if ch == ',' and angle == 0 and paren == 0:
                    params.append(''.join(buf).strip())
                    buf = []
                else:
                    buf.append(ch)
            if buf:
                params.append(''.join(buf).strip())

            def norm_param(p: str) -> str:
                p = re.sub(r"\s+", " ", p).strip()
                # Drop trailing parameter identifiers if any sneaked in
                p = re.sub(r"(\b[\w:<>*&\s]+?)\s+([A-Za-z_][A-Za-z0-9_]*)$", r"\1", p)
                # Move leading 'const ' to trailing ' const'
                leading_const = p.startswith('const ')
                if leading_const:
                    p = p[len('const '):].strip()
                m2 = re.match(r'^(.*?)(\s*[&*]+)$', p)
                if m2:
                    base = m2.group(1).strip()
                    syms = m2.group(2).replace(' ', '')
                else:
                    base = p
                    syms = ''
                if leading_const:
                    p = f"{base} const{syms}"
                else:
                    p = f"{base}{syms}"
                # Namespace spacing and pointer/ref spacing
                p = re.sub(r"\s*::\s*", "::", p)
                p = re.sub(r"\s+([&*])", r"\1", p)
                p = re.sub(r"<\s*", "<", p)
                # Ensure nested template closers have space
                p = p.replace(">>", "> >")
                return p

            norm_params = [norm_param(p) for p in params if p != '']
            norm_params_str = ', '.join(norm_params)
            out = f"{prefix}{norm_params_str}{suffix}"
            # Collapse whitespace and apply final normalizations
            out = re.sub(r"\s+", " ", out)
            out = re.sub(r"\s*::\s*", "::", out)
            out = re.sub(r",\s*", ", ", out)
            out = re.sub(r"\s+([&*])", r"\1", out)
            out = out.replace(">>", "> >")
            return out.strip() + line_part
        except Exception:
            return full_sig

    def load_coverage_mapping(self, coverage_json_path: str):
        with open(coverage_json_path, 'r') as f:
            self.coverage_map = json.load(f)

    def find_tests_for_functions(self, functions: List[str]) -> Dict:
        """Find unique tests that cover the given functions."""
        if not self.coverage_map:
            print("Error: Coverage mapping not loaded")
            return {
                'all_covering_tests': set(),
                'functions_with_tests': 0,
                'functions_without_tests': 0,
                'total_tests': 0,
                'function_test_counts': {},
                'test_function_counts': {},
                'direct_matches': 0,
                'path_removed_matches': 0
            }
        matcher = Matcher(self.coverage_map)
        return matcher.match(functions)
    
    def get_all_tests_from_coverage(self) -> Set[str]:
        """Get all unique tests from the coverage mapping."""
        if not self.coverage_map:
            return set()
        all_tests = set()
        for tests in self.coverage_map.values():
            if isinstance(tests, (list, set)):
                all_tests.update(tests)
            elif isinstance(tests, str):
                all_tests.add(tests)
        return all_tests


    def _get_comprehensive_system_includes(self) -> List[str]:
        """Get system include paths using GCC 14 toolchain (simplified approach like workflow)."""
        includes = []
        
        # CRITICAL: Use the same approach as the workflow - just --gcc-toolchain=/usr
        # This lets clang automatically find the correct include paths
        includes.extend(['--gcc-toolchain=/usr'])
        # Add clang resource directory if available (for built-in headers)
        crd = self._clang_resource_dir()
        if crd:
            includes.extend(['-resource-dir', crd])
        return includes


    def _build_clang_args(self) -> List[str]:
        """Build unified clang arguments for CVC5 parsing."""
        args = [
            # Force C++ mode for header files
            '-x', 'c++',
            # C++ standard
            '-std=c++17',
            '-gz=none',  # Disable debug section compression
            # Include paths (critical for CVC5)
            '-I./include',                    # Public headers
            '-I./build/include',              # Generated headers
            '-I./src/include',                # Internal headers
            '-I./src/.',                      # Source directory
            '-I./build/src',                  # Build source directory
            '-isystem', './build/deps/include',  # Dependencies
            
            # CVC5-specific preprocessor definitions
            '-DCVC5_ASSERTIONS',
            '-DCVC5_DEBUG', 
            '-DCVC5_STATISTICS_ON',
            '-DCVC5_TRACING',
            '-DCVC5_USE_POLY',
            '-D__BUILDING_CVC5LIB',
            '-Dcvc5_obj_EXPORTS',
            
            # Compiler flags used by CVC5
            '-Wall',
            '-Wsuggest-override',
            '-Wnon-virtual-dtor', 
            '-Wimplicit-fallthrough',
            '-Wshadow',
            '-fno-operator-names',
            '-Wno-deprecated-declarations',
            '-Wno-error=deprecated-declarations',
            '-fPIC',
            '-fvisibility=default',
            
            # Additional flags for better parsing
            '-fparse-all-comments',
            '-Wno-unknown-pragmas',
            '-Wno-unused-parameter',
            '-Wno-unused-variable',
            '-Wno-unused-function'
        ]
        
        # Add unified system includes (avoiding conflicts and duplicates)
        args.extend(self._get_comprehensive_system_includes())
        
        return args

    
    def cleanup_coverage_mapping(self):
        """Clean up coverage mapping from memory."""
        self.coverage_map = None
        gc.collect()
    
    def analyze_commit_coverage(self, commit_hash: str, coverage_json_path: str) -> Dict:
        """Complete analysis: get functions from commit and find covering tests."""
        print(f"Analyzing commit {commit_hash}...")
        
        # Step 1: Get changed functions from commit
        changed_functions, files_with_no_functions = self.get_commit_functions(commit_hash)
        
        # Step 2: Load coverage mapping
        self.load_coverage_mapping(coverage_json_path)
        
        if not changed_functions:
            # No functions found - check if we should fallback to all tests
            if files_with_no_functions:
                print(f"Warning: {len(files_with_no_functions)} .cpp/.hpp file(s) changed but no functions detected:")
                for f in files_with_no_functions:
                    print(f"  - {f}")
                print("Including all tests from coverage mapping as fallback.")
                all_tests = self.get_all_tests_from_coverage()
                self.cleanup_coverage_mapping()
                return {
                    'commit': commit_hash,
                    'changed_functions': [],
                    'files_with_no_functions': files_with_no_functions,
                    'covering_tests': sorted(list(all_tests)),
                    'function_matches': {},
                    'match_type_counts': {},
                    'summary': {
                        'total_functions': 0,
                        'functions_with_tests': 0,
                        'functions_without_tests': 0,
                        'total_covering_tests': len(all_tests),
                        'coverage_percentage': 0,
                        'fallback_to_all_tests': True
                    }
                }
            else:
                print("No functions found in commit")
                self.cleanup_coverage_mapping()
                return {
                    'commit': commit_hash,
                    'changed_functions': [],
                    'covering_tests': [],
                    'function_matches': {},
                    'match_type_counts': {},
                    'summary': {
                        'total_functions': 0,
                        'functions_with_tests': 0,
                        'functions_without_tests': 0,
                        'total_covering_tests': 0,
                        'coverage_percentage': 0,
                        'fallback_to_all_tests': False
                    }
                }
        
        # Step 3: Find tests for the changed functions
        test_results = self.find_tests_for_functions(changed_functions)
        
        # Step 4: Check if we should fallback to all tests
        # Fallback conditions:
        # 1. No direct matches AND files with no functions detected, OR
        # 2. No functions have tests mapped (coverage = 0%), OR
        # 3. No tests found at all
        should_fallback = False
        fallback_reason = ""
        
        if test_results['direct_matches'] == 0 and files_with_no_functions:
            should_fallback = True
            fallback_reason = f"{len(files_with_no_functions)} .cpp/.hpp file(s) changed but no functions detected"
        elif test_results['functions_with_tests'] == 0 and changed_functions:
            should_fallback = True
            fallback_reason = f"No tests mapped to {len(changed_functions)} changed function(s) (coverage = 0%)"
        elif test_results['total_tests'] == 0:
            should_fallback = True
            fallback_reason = "No tests found in coverage mapping"
        
        if should_fallback:
            print(f"Warning: {fallback_reason}")
            if files_with_no_functions:
                for f in files_with_no_functions:
                    print(f"  - {f}")
            print(f"No direct matches found ({test_results['direct_matches']} direct matches).")
            print("Including all tests from coverage mapping as fallback.")
            all_tests = self.get_all_tests_from_coverage()
            self.cleanup_coverage_mapping()
            return {
                'commit': commit_hash,
                'changed_functions': changed_functions,
                'files_with_no_functions': files_with_no_functions,
                'covering_tests': sorted(list(all_tests)),
                'function_matches': test_results.get('function_matches', {}),
                'match_type_counts': test_results.get('match_type_counts', {}),
                'summary': {
                    'total_functions': len(changed_functions),
                    'functions_with_tests': test_results['functions_with_tests'],
                    'functions_without_tests': test_results['functions_without_tests'],
                    'total_covering_tests': len(all_tests),
                    'coverage_percentage': (test_results['functions_with_tests'] / len(changed_functions) * 100) if changed_functions else 0,
                    'fallback_to_all_tests': True
                }
            }
        
        # Step 5: Clean up memory
        self.cleanup_coverage_mapping()
        
        # Step 6: Generate detailed statistics
        summary = {
            'total_functions': len(changed_functions),
            'functions_with_tests': test_results['functions_with_tests'],
            'functions_without_tests': test_results['functions_without_tests'],
            'total_covering_tests': test_results['total_tests'],
            'coverage_percentage': (test_results['functions_with_tests'] / len(changed_functions) * 100) if changed_functions else 0,
            'fallback_to_all_tests': False
        }
        
        print(
            f"Changed functions: {summary['total_functions']}; "
            f"with coverage: {summary['functions_with_tests']}; "
            f"without: {summary['functions_without_tests']}; "
            f"unique tests: {summary['total_covering_tests']}; "
            f"coverage: {summary['coverage_percentage']:.1f}%"
        )
        
        # Output selected functions and match breakdown
        print("\nFunctions selected from commit:")
        for f in changed_functions:
            mt = test_results.get('function_matches', {}).get(f, {}).get('match_type', 'none')
            cnt = test_results.get('function_test_counts', {}).get(f, 0)
            print(f"  {f} -> {mt} (tests={cnt})")
        
        mcounts = test_results.get('match_type_counts', {})
        if mcounts:
            print("\nMatch breakdown:")
            for k in sorted(mcounts.keys()):
                print(f"  {k}: {mcounts[k]}")
        
        return {
            'commit': commit_hash,
            'changed_functions': changed_functions,
            'covering_tests': sorted(list(test_results['all_covering_tests'])),
            'function_matches': test_results.get('function_matches', {}),
            'match_type_counts': test_results.get('match_type_counts', {}),
            'summary': summary
        }
    

def main():
    parser = argparse.ArgumentParser(description='Analyze commit coverage using coverage mapping')
    parser.add_argument('commit', help='Commit hash to analyze')
    parser.add_argument('--coverage-json', default='coverage_mapping.json', 
                       help='Path to coverage mapping JSON file')
    parser.add_argument('--compile-commands', default=None,
                       help='Path to compile_commands.json or its directory (for Clang args)')
    parser.add_argument('--output-matrix', help='Output matrix to JSON file instead of console')
    parser.add_argument('--output-changed-functions', help='Output changed functions list to JSON file')
    parser.add_argument('--tests-per-job', type=int, default=1, 
                       help='Number of tests to group per job (default: 1)')
    parser.add_argument('--max-jobs', type=int, default=None,
                       help='Maximum number of jobs to create (default: unlimited)')
    
    args = parser.parse_args()
    
    # Check if coverage JSON exists
    if not os.path.exists(args.coverage_json):
        print(f"Error: Coverage JSON file not found: {args.coverage_json}")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = PrepareCommitAnalyzer(".", compile_commands=args.compile_commands)
    
    # Analyze commit coverage
    result = analyzer.analyze_commit_coverage(args.commit, args.coverage_json)
    
    # Get unique tests
    unique_tests = sorted(list(set(result['covering_tests'])))
    
    # Always output summary (only once)
    print(f"Changed functions: {result['summary']['total_functions']}; "
          f"with coverage: {result['summary']['functions_with_tests']}; "
          f"without: {result['summary']['functions_without_tests']}; "
          f"unique tests: {result['summary']['total_covering_tests']}; "
          f"coverage: {result['summary']['coverage_percentage']:.1f}%")
    
    if args.output_matrix:
        total_tests = len(unique_tests)
        max_jobs = args.max_jobs
        
        # Calculate optimal tests_per_job to stay under max_jobs limit
        if max_jobs is not None and total_tests > 0:
            # If user specified tests_per_job explicitly, check if it fits
            if args.tests_per_job != 1:  # User explicitly set it
                calculated_jobs = (total_tests + args.tests_per_job - 1) // args.tests_per_job
                if calculated_jobs > max_jobs:
                    print(f"Warning: {args.tests_per_job} tests per job would create {calculated_jobs} jobs (exceeds max {max_jobs})")
                    # Calculate optimal value
                    tests_per_job = max(1, (total_tests + max_jobs - 1) // max_jobs)  # ceil division
                    actual_jobs = (total_tests + tests_per_job - 1) // tests_per_job
                    print(f"Using calculated value: {tests_per_job} tests per job = {actual_jobs} jobs")
                else:
                    tests_per_job = args.tests_per_job
                    actual_jobs = calculated_jobs
            else:
                # Calculate optimal tests_per_job to fit within max_jobs
                tests_per_job = max(1, (total_tests + max_jobs - 1) // max_jobs)  # ceil division
                actual_jobs = (total_tests + tests_per_job - 1) // tests_per_job  # ceil division
            
            print(f"Total tests: {total_tests}, max_jobs: {max_jobs}")
            print(f"Allocation: {tests_per_job} tests per job = {actual_jobs} jobs")
        else:
            # No max_jobs limit, use user-specified or default
            tests_per_job = args.tests_per_job
            actual_jobs = (total_tests + tests_per_job - 1) // tests_per_job if total_tests > 0 else 0
        
        # Group tests into jobs using two-phase deterministic proportional interleaving
        # (Supermarket algorithm / Bresenham for N dimensions)
        # This ensures tests for each function are evenly distributed across jobs
        jobs = []
        function_matches = result.get('function_matches', {})
        
        # Check if we have function matches (fallback to sequential if not)
        if function_matches and any(match.get('tests') for match in function_matches.values()):
            # Multi-queue system: group tests by function
            function_queues = {}
            for func, match_data in function_matches.items():
                func_tests = match_data.get('tests', [])
                if func_tests:
                    function_queues[func] = list(func_tests)
            
            if function_queues:
                # Two-phase approach: Phase 1 (allocation) + Phase 2 (interleaving)
                for job_id in range(actual_jobs):
                    # Phase 1: Compute exact count per function for this job
                    this_job_counts = {}
                    for func, tests in function_queues.items():
                        n = len(tests)
                        base = n // actual_jobs
                        if job_id < n % actual_jobs:
                            base += 1
                        if base > 0:
                            this_job_counts[func] = base
                    
                    # Phase 2: Supermarket interleaving (Bresenham-style)
                    pointers = {f: 0 for f in this_job_counts}
                    accum = {f: 0.0 for f in this_job_counts}
                    weights = {f: len(function_queues[f]) for f in this_job_counts}
                    job_tests = []
                    
                    total_in_job = sum(this_job_counts.values())
                    total_weight = sum(weights.values())
                    
                    while len(job_tests) < total_in_job:
                        best_func = None
                        best_score = -1
                        
                        for func in this_job_counts:
                            if pointers[func] < this_job_counts[func]:
                                accum[func] += weights[func]
                                if accum[func] > best_score:
                                    best_score = accum[func]
                                    best_func = func
                        
                        if best_func is None:
                            break
                        
                        test = function_queues[best_func][pointers[best_func]]
                        job_tests.append(test)
                        pointers[best_func] += 1
                        accum[best_func] -= total_weight
                    
                    jobs.append({
                        'job_id': job_id,
                        'tests': job_tests
                    })
            else:
                # No function queues, fallback to sequential split
                for i in range(0, total_tests, tests_per_job):
                    job_tests = unique_tests[i:i + tests_per_job]
                    job_id = i // tests_per_job
                    jobs.append({
                        'job_id': job_id,
                        'tests': job_tests
                    })
        else:
            # Fallback: no function matches, use sequential split
            for i in range(0, total_tests, tests_per_job):
                job_tests = unique_tests[i:i + tests_per_job]
                job_id = i // tests_per_job
                jobs.append({
                    'job_id': job_id,
                    'tests': job_tests
                })
        
        matrix_data = {
            'matrix': {'include': jobs},
            'total_tests': total_tests,
            'total_jobs': len(jobs),
            'tests_per_job': tests_per_job
        }
        
        with open(args.output_matrix, 'w') as f:
            json.dump(matrix_data, f, indent=2)
        
        print(f"Matrix written to {args.output_matrix} with {total_tests} tests in {len(jobs)} jobs ({tests_per_job} tests per job)")
    
    # Save changed functions if requested
    if args.output_changed_functions:
        changed_functions_data = {
            'commit_hash': args.commit,
            'changed_functions': result['changed_functions']
        }
        with open(args.output_changed_functions, 'w') as f:
            json.dump(changed_functions_data, f, indent=2)
        print(f"Changed functions written to {args.output_changed_functions} ({len(result['changed_functions'])} functions)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
