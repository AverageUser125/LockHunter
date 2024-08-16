#!/usr/bin/env python3
# coding: UTF-8
# Copyright (c) 2019-2024 Matus Chochlik
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt

from typing import List, Optional, TextIO, Self, Any, Iterator, Dict, Generator, Union, BinaryIO, Tuple
from types import TracebackType
import os
import re
import sys
import errno
import getpass
import logging
import hashlib
import tempfile
import subprocess
import json
import shlex
import sys
import time
import traceback
import typing as tp
import glob

# Determine the script directory
script_dir = os.path.dirname(os.path.abspath(__file__))

# Call clang-format with the style file
clang_format_cmd = [
    'clang-format', '-i', f'-style=file:{script_dir}/../.clang-format'
]

redis = None

# ------------------------------------------------------------------------------
def getenv_boolean_flag(name: str) -> bool:
    return os.getenv(name, "0").lower() in ["true", "1", "yes", "y", "on"]

# ------------------------------------------------------------------------------
def mkdir_p(path: str) -> None:
    try:
        os.makedirs(path)
    except OSError as os_error:
        if os_error.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


    
# ------------------------------------------------------------------------------
class ClangTidyCacheOpts(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log: logging.Logger, args: list[str]):
        self._log = log
        self._directories_with_clang_tidy = []

        # Define the prefix used to identify directories with clang-tidy
        prefix = '--directories_with_clang_tidy='

        # Iterate through the command line arguments
        for index, arg in enumerate(args):
            if arg.startswith(prefix):
                # Split the argument using '*' as a separator to get a list
                # of directories, I used '*' because a folder cannot contain
                # this character in its name whereas it can contain `,`
                self._directories_with_clang_tidy = arg[len(prefix):].split('*')

                # Remove the argument because clang-tidy will not like it
                args.pop(index)

                break

        if len(args) < 1:
            self._log.error("Missing arguments")

        self._original_args = args
        self._clang_tidy_args: list[str] = []
        self._compiler_args: list[str] = []
        self._cache_dir: Optional[str] = None
        self._compile_commands_db: Optional[List[Dict[str, Any]]]= None

        self._strip_list = os.getenv("CTCACHE_STRIP", "").split(os.pathsep)

        args = self._split_compiler_clang_tidy_args(args)
        self._adjust_compiler_args(args)

    # --------------------------------------------------------------------------
    def __repr__(self: Self) -> str:
        return \
            f"ClangTidyCacheOpts(" \
                f"clang_tidy_args:{self._clang_tidy_args}," \
                f"compiler_args:{self._compiler_args}," \
                f"original_args:{self._original_args}" \
            f")"

    # --------------------------------------------------------------------------
    def running_on_msvc(self: Self) -> bool:
        if self._compiler_args:
           return os.path.basename(self._compiler_args[0]) == "cl.exe"
        return False

    # --------------------------------------------------------------------------
    def running_on_clang_cl(self: Self) -> bool:
        if self._compiler_args:
           return os.path.basename(self._compiler_args[0]) == "clang-cl.exe"
        return False

    # --------------------------------------------------------------------------
    def _split_compiler_clang_tidy_args(self: Self, argsIn: List[str]) -> list[str]:
        # splits arguments starting with - on the first =
        split_args: List[List[str]] = [arg.split('=', 1) if arg.startswith('-p') else [arg] for arg in argsIn]
        args: List[str] = [item for sublist in split_args for item in sublist]

        if args.count("--") == 1:
            # Invoked with compiler args on the actual command line
            i = args.index("--")
            self._clang_tidy_args = args[:i]
            self._compiler_args = args[i+1:]
        elif args.count("-p") == 1:
            # Invoked with compiler args in a compile commands json db
            i = args.index("-p")
            self._clang_tidy_args = args

            i += 1
            if i >= len(args):
                return []

            cdb_path = args[i]
            cdb = os.path.join(cdb_path, "compile_commands.json")
            self._load_compile_command_db(cdb)

            i += 1
            if i >= len(args):
                return []

            # This assumes that the filename occurs after the -p <cdb path>
            # and that there is only one of them
            filenames = [arg for arg in args[i:] if not arg.startswith("-")]
            if len(filenames) > 0:
                self._compiler_args = self._compiler_args_for(filenames[0])
        else:
            # Invoked as pure clang-tidy command
            self._clang_tidy_args = args[1:]
        return args

    # --------------------------------------------------------------------------
    def _adjust_compiler_args(self: Self, args: list[str]) -> None:
        if self._compiler_args:
            pos = next((pos for pos, arg in enumerate(self._compiler_args) if arg.startswith('-D')), 1)
            self._compiler_args.insert(pos, "-D__clang_analyzer__=1")
            for i in range(1, len(self._compiler_args)):
                if self._compiler_args[i-1] in ["-o", "--output"]:
                    self._compiler_args[i] = "-"
                if self._compiler_args[i-1] in ["-c"]:
                    self._compiler_args[i-1] = "-E"
            for i in range(1, len(self._compiler_args)):
                if self._compiler_args[i-1] in ["-E"]:
                    if self.running_on_msvc():
                        self._compiler_args[i-1] = "-EP"
                    else:
                        self._compiler_args.insert(i, "-P")

    # --------------------------------------------------------------------------
    def _load_compile_command_db(self: Self, filename: str) -> bool:
        try:
            with open(filename) as f:
                js = f.read().replace(r'\\\"', "'").replace("\\", "\\\\")
                self._compile_commands_db = json.loads(js)
        except Exception as err:
            self._log.error("Loading compile command DB failed: {0}".format(repr(err)))
            return False
        return True

    # --------------------------------------------------------------------------
    def _compiler_args_for(self: Self, filename: str) -> list[str]:
        if self._compile_commands_db is None:
                return []
            
        compile_commands = self._compile_commands_db

        filename = os.path.expanduser(filename)
        filename = os.path.realpath(filename)

        for command in compile_commands or []:
            db_filename = command.get("file", "")
            try:
                if os.path.samefile(filename, db_filename):
                    try:
                        return shlex.split(command["command"])
                    except KeyError:
                        try:
                            return shlex.split(command["arguments"][0])
                        except IndexError:
                            return ["clang-tidy"]
            except FileNotFoundError:
                continue

        return []

    # --------------------------------------------------------------------------
    def should_print_dir(self: Self) -> bool:
        try:
            return self._original_args[0] == "--cache-dir"
        except IndexError:
            return False

    # --------------------------------------------------------------------------
    def should_print_stats(self: Self) -> bool:
        try:
            return self._original_args[0] == "--show-stats"
        except IndexError:
            return False

    # --------------------------------------------------------------------------
    def should_print_stats_raw(self: Self) -> bool:
        try:
            return self._original_args[0] == "--print-stats"
        except IndexError:
            return False

    # --------------------------------------------------------------------------
    def should_remove_dir(self: Self) -> bool:
        try:
            return self._original_args[0] == "--clean"
        except IndexError:
            return False

    # --------------------------------------------------------------------------
    def should_zero_stats(self: Self) -> bool:
        try:
            return self._original_args[0] == "--zero-stats"
        except IndexError:
            return False

    # --------------------------------------------------------------------------
    def directories_with_clang_tidy(self: Self) -> list[str]:
        return self._directories_with_clang_tidy

    # --------------------------------------------------------------------------
    def original_args(self: Self) -> list[str]:
        return self._original_args

    # --------------------------------------------------------------------------
    def clang_tidy_args(self: Self) -> list[str]:
        return self._clang_tidy_args

    # --------------------------------------------------------------------------
    def compiler_args(self: Self) -> list[str]:
        return self._compiler_args

    # --------------------------------------------------------------------------
    @property
    def cache_dir(self: 'Self') -> str:
        if self._cache_dir:
            return self._cache_dir

        try:
            user = getpass.getuser()
        except KeyError:
            user = "unknown"

        temp_dir = tempfile.tempdir if tempfile.tempdir else os.getenv("TEMP", "%temp%")

        self._cache_dir = os.getenv(
            "CTCACHE_DIR",
            os.path.join(temp_dir, "ctcache-" + user)
        )
        return self._cache_dir

     # --------------------------------------------------------------------------
    def strip_paths(self: Self, input: str) -> str:
        for item in self._strip_list:
            input = re.sub(item, '', input)
        return input

    # --------------------------------------------------------------------------
    def adjust_chunk(self: Self, x: str) -> bytes:
        x = x.strip()
        r = str().encode("utf8")
        if not x.startswith("# "):
            for w in x.split():
                w = w.strip('"')
                if os.path.exists(w):
                    w = os.path.realpath(w)
                w = self.strip_paths(w)
                w.strip()
                if w:
                    r += w.encode("utf8")
        return r

    # --------------------------------------------------------------------------
    def has_host(self: Self) -> bool:
        return os.getenv("CTCACHE_HOST") is not None

    # --------------------------------------------------------------------------
    def rest_host(self: Self) -> str:
        return os.getenv("CTCACHE_HOST", "localhost")

    # --------------------------------------------------------------------------
    def rest_proto(self: Self) -> str:
        return os.getenv("CTCACHE_PROTO", "http")

    # --------------------------------------------------------------------------
    def rest_port(self: Self) -> int:
        return int(os.getenv("CTCACHE_PORT", 5000))

    # --------------------------------------------------------------------------
    def rest_host_read_only(self: Self) -> bool:
        return getenv_boolean_flag("CTCACHE_HOST_READ_ONLY")

    # --------------------------------------------------------------------------
    def save_output(self: Self) -> bool:
        return getenv_boolean_flag("CTCACHE_SAVE_OUTPUT")

    # --------------------------------------------------------------------------
    def ignore_output(self: Self) -> bool:
        return self.save_output() or "CTCACHE_IGNORE_OUTPUT" in os.environ

    # --------------------------------------------------------------------------
    def save_all(self: Self) -> bool:
        return self.save_output() or "CTCACHE_SAVE_ALL" in os.environ

    # --------------------------------------------------------------------------
    def debug_enabled(self: Self) -> bool:
        return getenv_boolean_flag("CTCACHE_DEBUG")

    # --------------------------------------------------------------------------
    def dump_enabled(self: Self) -> bool:
        return getenv_boolean_flag("CTCACHE_DUMP")

    # --------------------------------------------------------------------------
    def dump_dir(self: Self) -> str:
        return os.getenv("CTCACHE_DUMP_DIR", tempfile.gettempdir())

    # --------------------------------------------------------------------------
    def strip_src(self: Self) -> bool:
        return getenv_boolean_flag("CTCACHE_STRIP_SRC")

    # --------------------------------------------------------------------------
    def exclude_hash_regex(self: Self) -> Optional[str]:
        return os.getenv("CTCACHE_EXCLUDE_HASH_REGEX")

    # --------------------------------------------------------------------------
    def exclude_hash(self: Self, chunk: bytes) -> bool:
        regex = self.exclude_hash_regex()
        return bool(regex and re.match(regex, chunk.decode("utf8")))

# ------------------------------------------------------------------------------
class ClangTidyCache(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log: logging.Logger, opts: ClangTidyCacheOpts):
        self._log = log
        self._opts = opts
        self._local = None
        self._remote = None

        caches: List[ClangTidyCache] = []

        if not caches or opts.cache_locally():
            local = ClangTidyLocalCache(log, opts)
            self._local = self._wrap_with_stats(local, "stats")

        if caches:
            remote = ClangTidyMultiCache(log, caches)
            self._remote = self._wrap_with_stats(remote, "remote_stats")

    # --------------------------------------------------------------------------
    def _wrap_with_stats(self: Self, cache: ClangTidyCache | ClangTidyMultiCache, name: str) -> ClangTidyCacheWithStats:
        if not self._opts.no_local_stats():
            stats = ClangTidyCacheStats(self._log, self._opts, name)
            return ClangTidyCacheWithStats(self._log, self._opts, cache, stats)
        return cache

    # --------------------------------------------------------------------------
    def is_cached(self: Self, digest: str) -> bool:
        if self._local:
            if self._local.is_cached(digest):
                return True

        if self._remote:
            if self._remote.is_cached(digest):
                if self.should_writeback():
                    self._local.store_in_cache(digest)
                return True

        return False

    # --------------------------------------------------------------------------
    def get_cache_data(self: Self, digest: str) -> tp.Optional[bytes]:
        if self._local:
            data = self._local.get_cache_data(digest)
            if data is not None:
                return data

        if self._remote:
            data = self._remote.get_cache_data(digest)
            if data is not None:
                if self.should_writeback():
                    self._local.store_in_cache_with_data(digest, data)
                return data

        return None

    # --------------------------------------------------------------------------
    def store_in_cache(self: Self, digest: str) -> None:
        if self._local:
            self._local.store_in_cache(digest)

        if self._remote:
            self._remote.store_in_cache(digest)

    # --------------------------------------------------------------------------
    def store_in_cache_with_data(self: Self, digest: str, data: bytes) -> None:
        if self._local:
            self._local.store_in_cache_with_data(digest, data)

        if self._remote:
            self._remote.store_in_cache_with_data(digest, data)

    # --------------------------------------------------------------------------
    def query_stats(self: Self, options: ClangTidyCacheOpts) -> dict[str, Any]:
        stats = {}

        if self._local:
            stats["local"] = self._local.query_stats(options)

        if self._remote:
            stats["remote"] = self._remote.query_stats(options)

        return stats

    # --------------------------------------------------------------------------
    def clear_stats(self: Self, options: ClangTidyCacheOpts) -> None:
        if self._local:
            self._local.clear_stats(options)

        if self._remote:
            self._remote.clear_stats(options)

    # --------------------------------------------------------------------------
    def should_writeback(self: Self):
        return self._local is not None and not self._opts.no_local_writeback()
# ------------------------------------------------------------------------------
class ClangTidyCacheHash(object):
    # --------------------------------------------------------------------------
    def _opendump(self: Self, opts: ClangTidyCacheOpts) -> BinaryIO:
        return open(os.path.join(opts.dump_dir(), "ctcache.dump"), "ab")

    # --------------------------------------------------------------------------
    def __init__(self: Self, opts: ClangTidyCacheOpts):
        self._hash = hashlib.sha1()
        self._dump: Optional[BinaryIO] = None
        if opts.dump_enabled():
            self._dump = self._opendump(opts)

        assert self._dump or not opts.dump_enabled()

    # --------------------------------------------------------------------------
    def __del__(self: Self) -> None:
        if self._dump:
            self._dump.close()

    # --------------------------------------------------------------------------
    def update(self: Self, content: bytes) -> None:
        if content:
            self._hash.update(content)
            if self._dump:
                self._dump.write(content)

    # --------------------------------------------------------------------------
    def hexdigest(self: Self) -> str:
        return self._hash.hexdigest()

# ------------------------------------------------------------------------------
class MultiprocessLock:
    # --------------------------------------------------------------------------
    def __init__(self: Self, lock_path: str, timeout: int = 3): # timeout 3 seconds
        self._lock_path = os.path.abspath(os.path.expanduser(lock_path))
        self._timeout = timeout
        self._lock_handle: Optional[int] = None

    # --------------------------------------------------------------------------
    def acquire(self: Self) -> Self:
        start_time = time.time()
        while True:
            try:
                # Attempt to create the lock file exclusively
                self._lock_handle = os.open(self._lock_path, os.O_CREAT | os.O_EXCL)
                return self
            except FileExistsError:
                # File is locked, check if the timeout has been exceeded
                if time.time() - start_time > self._timeout:
                    msg = f"Timeout ({self._timeout} seconds) exceeded while acquiring lock."
                    raise RuntimeError(msg)
                # Wait and try again
                time.sleep(0.1)
            except FileNotFoundError:
                # The path to the lock file doesn't exist, create it and retry
                os.makedirs(os.path.dirname(self._lock_path), exist_ok=True)

    # --------------------------------------------------------------------------
    def release(self: Self) -> None:
        if self._lock_handle is not None:
            try:
                os.close(self._lock_handle)
                os.unlink(self._lock_path)  # Remove the lock file upon release
            except OSError:
                pass  # Ignore errors if the file doesn't exist or has already been released
            finally:
                self._lock_handle = None

    # --------------------------------------------------------------------------
    def __enter__(self: Self) -> Self:
        return self.acquire()

    # --------------------------------------------------------------------------
    def __exit__(self: Self, exc_type: type, exc_value: BaseException, traceback: TracebackType) -> None:
        self.release()

# ------------------------------------------------------------------------------
class ClangTidyCacheStats(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log: logging.Logger, opts: ClangTidyCacheOpts, name: str):
        self._log = log
        self._opts = opts
        self._name = name

    # --------------------------------------------------------------------------
    def stats_file(self: Self, digest: str) -> str:
        return os.path.join(self._opts.cache_dir, digest[:2], self._name)

    # --------------------------------------------------------------------------
    def read(self: Self) -> tuple[int, int]:
        hits, misses = 0, 0
        for i in range(0, 256):
            digest = f'{i:x}'
            file = self.stats_file(digest)
            if os.path.isfile(file):
                h, m = self._read(file)
                hits += h
                misses += m
        return hits, misses

    # --------------------------------------------------------------------------
    def _read(self: Self, file: str) -> tuple[int, int]:
        with MultiprocessLock(file + ".lock") as _:
            if os.path.isfile(file):
                with open(file, 'r') as f:
                    return self.read_from_file(f)
            return 0,0

    # --------------------------------------------------------------------------
    def read_from_file(self: Self, f: TextIO) -> tuple[int, int]:
        content = f.read().split()
        if len(content) == 2:
            return int(content[0]), int(content[1])
        else:
            self._log.error(f"Invalid stats content in: {f.name}")
        return 0,0

    # --------------------------------------------------------------------------
    def write_to_file(self: Self, f, hits, misses, hit):
        if hit:
            hits += 1
        else:
            misses += 1
        f.write(f"{hits} {misses}\n")

    # --------------------------------------------------------------------------
    def update(self: Self, digest, hit):
        try:
            file = self.stats_file(digest)
            mkdir_p(os.path.dirname(file))
            with MultiprocessLock(file + ".lock") as _:
                try:
                    if os.path.isfile(file):
                        with open(file, 'r+') as fh:
                            hits, misses = self.read_from_file(fh)
                            fh.seek(0)
                            self.write_to_file(fh, hits, misses, hit)
                            fh.truncate()
                    else:
                        with open(file, 'w') as fh:
                            self.write_to_file(fh, 0, 0, hit)
                except IOError as e:
                    self._log.error(f"Error writing to file: {e}")
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            raise

    # --------------------------------------------------------------------------
    def clear(self: Self):
        for i in range(0, 256):
            digest = f'{i:x}'
            file = self.stats_file(digest)
            if os.path.isfile(file):
                os.unlink(file)

# ------------------------------------------------------------------------------
class ClangTidyLocalCache(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log, opts):
        self._log = log
        self._opts = opts
        self._hash_regex = re.compile(r'^[0-9a-f]{38}$')

    # --------------------------------------------------------------------------
    def is_cached(self: Self, digest):
        path = self._make_path(digest)
        if os.path.isfile(path):
            os.utime(path, None)
            return True

        return False

    # --------------------------------------------------------------------------
    def get_cache_data(self: Self, digest: str) -> tp.Optional[bytes]:
        path = self._make_path(digest)
        if os.path.isfile(path):
            os.utime(path, None)
            with open(path, "rb") as stream:
                return stream.read()
        else:
            return None

    # --------------------------------------------------------------------------
    def store_in_cache(self: Self, digest: str) -> None:
        p = self._make_path(digest)
        mkdir_p(os.path.dirname(p))
        open(p, "w").close()

    # --------------------------------------------------------------------------
    def store_in_cache_with_data(self: Self, digest: str, data: bytes) -> None:
        p = self._make_path(digest)
        mkdir_p(os.path.dirname(p))
        with open(p, "wb") as stream:
            stream.write(data)

    def _list_cached_files(self: 'Self', options: 'ClangTidyCacheOpts', prefix: str) -> Iterator[Tuple[str, str, str]]:
        for root, dirs, files in os.walk(prefix):
            for prefix in dirs:
                # Recursively list files in directories
                for file_info in self._list_cached_files(options, os.path.join(root, prefix)):
                    if self._hash_regex.match(file_info[2]):  # file_info[2] is the filename
                        yield root, prefix, file_info[2]
            for filename in files:
                if self._hash_regex.match(filename):
                    yield root, prefix, filename

    # --------------------------------------------------------------------------
    def query_stats(self: Self, options: ClangTidyCacheOpts) -> Dict[str, Any]:
        hash_count = sum(1 for x in self._list_cached_files(options, options.cache_dir))
        return {"cached_count": hash_count}

    # --------------------------------------------------------------------------
    def clear_stats(self: Self, options):
        pass

    # --------------------------------------------------------------------------
    def _make_path(self: Self, digest):
        return os.path.join(self._opts.cache_dir, digest[:2], digest[2:])

# ------------------------------------------------------------------------------
class ClangTidyMultiCache(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log: logging.Logger, caches: List[ClangTidyCache]):
        self._log = log
        self._caches = caches

    # --------------------------------------------------------------------------
    def is_cached(self: Self, digest):
        for cache in self._caches:
            if cache.is_cached(digest):
                return True

        return False

    # --------------------------------------------------------------------------
    def get_cache_data(self: Self, digest) -> tp.Optional[bytes]:
        for cache in self._caches:
            data = cache.get_cache_data(digest)
            if data is not None:
                return data

        return None

    # --------------------------------------------------------------------------
    def store_in_cache(self: Self, digest):
        for cache in self._caches:
            cache.store_in_cache(digest)

    # --------------------------------------------------------------------------
    def store_in_cache_with_data(self: Self, digest, data: bytes):
        for cache in self._caches:
            cache.store_in_cache_with_data(digest, data)

    # --------------------------------------------------------------------------
    def query_stats(self: Self, options):
        for cache in self._caches:
            stats = cache.query_stats(options)
            if stats:
                return stats

        return {}

    # --------------------------------------------------------------------------
    def clear_stats(self: Self, options: ClangTidyCacheOpts) -> None:
        for cache in self._caches:
            cache.clear_stats(options)

# ------------------------------------------------------------------------------
class ClangTidyCacheWithStats(object):
    # --------------------------------------------------------------------------
    def __init__(self: Self, log: logging.Logger, opts: ClangTidyCacheOpts, cache: ClangTidyCache, stats: ClangTidyCacheStats):
        self._log = log
        self._opts = opts
        self._cache = cache
        self._stats = stats

    # --------------------------------------------------------------------------
    def is_cached(self: Self, digest: str) -> bool:
        res = self._cache.is_cached(digest)
        if self._stats:
            self._stats.update(digest, res)
        return res

    # --------------------------------------------------------------------------
    def get_cache_data(self: Self, digest: str) -> tp.Optional[bytes]:
        res = self._cache.get_cache_data(digest)
        if self._stats:
            self._stats.update(digest, res is not None)
        return res

    # --------------------------------------------------------------------------
    def store_in_cache(self: Self, digest: str) -> None:
        self._cache.store_in_cache(digest)

    # --------------------------------------------------------------------------
    def store_in_cache_with_data(self: Self, digest: str, data: bytes) -> None:
        self._cache.store_in_cache_with_data(digest, data)

    # --------------------------------------------------------------------------
    def query_stats(self: Self, options: ClangTidyCacheOpts) -> dict[str, Any]:
        stats = self._cache.query_stats(options)
        if stats is None:
            stats = {}

        if self._stats:
            hits, misses = self._stats.read()
            total = hits + misses
            stats["hit_count"] = hits
            stats["miss_count"] = misses
            stats["hit_rate"] = hits/total if total else 0
            stats["miss_rate"] = misses/total if total else 0

        return stats

    # --------------------------------------------------------------------------
    def clear_stats(self: Self, options: ClangTidyCacheOpts) -> None:
        self._cache.clear_stats(options)
        if self._stats:
            self._stats.clear()

# ------------------------------------------------------------------------------
source_file_change_re = re.compile(r'#\s+\d+\s+"([^"]+)".*')

def source_file_changed(cpp_line: str) -> Optional[str]:
    found = source_file_change_re.match(cpp_line)
    if found:
        found_path = found.group(1)
        if os.path.isfile(found_path):
            return os.path.realpath(os.path.dirname(found_path))

# ------------------------------------------------------------------------------
def find_ct_config(search_path: str) -> Optional[str]:
    while search_path and search_path != "/":
        search_path = os.path.dirname(search_path)
        ct_config = os.path.join(search_path, '.clang-tidy')
        if os.path.isfile(ct_config):
            return ct_config

# ------------------------------------------------------------------------------
def hash_inputs(log: logging.Logger, opts: ClangTidyCacheOpts) -> Optional[str]:
    ct_args = opts.clang_tidy_args()
    co_args = opts.compiler_args()

    if not ct_args and not co_args:
        return None

    def _is_src_ext(s: str) -> bool:
        exts = [".cppm", ".cpp", ".c", ".cc", ".h", ".hpp", ".cxx"] 
        return any(s.lower().endswith(ext) for ext in exts)

    result = ClangTidyCacheHash(opts)

    # --- Source file content (potentially pre-processed)
    if len(co_args) == 0:
        for arg in ct_args[1:]:
            if os.path.exists(arg) and _is_src_ext(arg):
                with open(arg, "rb") as srcfd:
                    src_data_binary = srcfd.read()
                    if opts.strip_src():
                        src_data = src_data_binary.decode(encoding="utf-8")
                        src_data = opts.strip_paths(src_data)
                        src_data_binary = src_data.encode("utf-8")
                    result.update(src_data_binary)
    else:
        # Execute the compiler command defined by the compiler arguments. At this
        # point if we have compiler arguments with expect that it defines a valid
        # command to get the pre-processed output.
        # If we have a valid output this gets added to the hash.
        proc = subprocess.Popen(
            co_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        if opts.running_on_msvc() or opts.running_on_clang_cl():
            if proc.returncode != 0:
                return None
        else:
            if stderr:
                # make sure str and not bytes
                log.error(f"Error executing compile command: #{co_args}.\n#{stderr.decode(encoding='utf-8')}")
                return None

        if opts.strip_src():
            stdout_str = stdout.decode(encoding="utf-8")
            stdout_str = opts.strip_paths(stdout_str)
            stdout = stdout_str.encode("utf-8")

        result.update(stdout)

    for arg in ct_args[1:]:
        if os.path.exists(arg) and _is_src_ext(arg):
            source_file = os.path.normpath(os.path.realpath(arg))
            break

    # --- Config Contents ------------------------------------------------------

    config_directories = opts.directories_with_clang_tidy()
    
    ct_config_paths = set()

    for directory in config_directories:
        directory = os.path.normpath(directory.strip())
        common_path = os.path.commonpath([source_file, directory])

        if common_path == directory:
            ct_config_paths.add(os.path.join(directory, '.clang-tidy'))

    for ct_config in sorted(ct_config_paths):
        with open(ct_config, "rt") as ct_config:
            for line in ct_config:
                chunk = opts.adjust_chunk(line)
                result.update(chunk)

    # --- Clang-Tidy and Compiler Args -----------------------------------------

    def _omit_after(args: list[str], excl: list[str]) -> Generator[str, None, None]:
        omit_next = False
        for arg in args:
            omit_this = arg in excl
            if not omit_this and not omit_next:
                yield arg
            omit_next = omit_this

    ct_args = list(_omit_after(ct_args, ["-export-fixes"]))

    for chunk in sorted(set([opts.adjust_chunk(arg) for arg in ct_args[1:]])):
        if not opts.exclude_hash(chunk):
            result.update(chunk)

    for chunk in sorted(set([opts.adjust_chunk(arg) for arg in co_args[1:]])):
        if not opts.exclude_hash(chunk):
            result.update(chunk)

    return result.hexdigest()

# ------------------------------------------------------------------------------
def print_stats(log: logging.Logger, opts: ClangTidyCacheOpts, raw: bool) -> str:
    def _format_bytes(s):
        if s < 10000:
            return "%d B" % (s)
        if s < 10000000:
            return "%d kB" % (s / 1000)
        return "%d MB" % (s / 1000000)

    def _format_time(s):
        if s < 60:
            return "%d seconds" % (s)
        if s < 3600:
            return "%d minutes %d seconds" % (s / 60, s % 60)
        if s < 86400:
            return "%d hours %d minutes" % (s / 3600, (s / 60) % 60)
        if s < 604800:
            return "%d days %d hours" % (s / 86400, (s / 3600) % 24)
        if int(s / 86400) % 7 == 0:
            return "%d weeks" % (s / 604800)
        return "%d weeks %d days" % (s / 604800, (s / 86400) % 7)

    cache = ClangTidyCache(log, opts)
    stats = cache.query_stats(opts)

    if raw:
        print(json.dumps(stats))
        return ""

    entries = [
        ("Server host", lambda o, s: o.rest_host()),
        ("Server port", lambda o, s: "%d" % o.rest_port()),
        ("Long-term hit rate", lambda o, s: "%.1f %%" % (s["remote"]["total_hit_rate"] * 100.0)),
        ("Hit rate", lambda o, s: "%.1f %%" % (s["remote"]["hit_rate"] * 100.0)),
        ("Hit count", lambda o, s: "%d" % s["remote"]["hit_count"]),
        ("Miss count", lambda o, s: "%d" % s["remote"]["miss_count"]),
        ("Miss rate", lambda o, s: "%.1f %%" % (s["remote"]["miss_rate"] * 100.0)),
        ("Max hash age", lambda o, s: "%d days" % max(int(k) for k in s["remote"]["age_days_histogram"])),
        ("Max hash hits", lambda o, s: "%d" % max(int(k) for k in s["remote"]["hit_count_histogram"])),
        ("Cache size", lambda o, s: _format_bytes(s["remote"]["saved_size_bytes"])),
        ("Cached hashes", lambda o, s: "%d" % s["remote"]["cached_count"]),
        ("Cleaned hashes", lambda o, s: "%d" % s["remote"]["cleaned_count"]),
        ("Cleaned ago", lambda o, s: _format_time(s["remote"]["cleaned_seconds_ago"])),
        ("Saved ago", lambda o, s: _format_time(s["remote"]["saved_seconds_ago"])),
        ("Uptime", lambda o, s: _format_time(s["remote"]["uptime_seconds"])),
        ("Hit rate (local)", lambda o, s: "%.1f %%" % (s["local"]["hit_rate"] * 100.0)),
        ("Hit count (local)", lambda o, s: "%d" % s["local"]["hit_count"]),
        ("Miss count (local)", lambda o, s: "%d" % s["local"]["miss_count"]),
        ("Miss rate (local)", lambda o, s: "%.1f %%" % (s["local"]["miss_rate"] * 100.0)),
        ("Cached hashes (local)", lambda o, s: "%d" % s["local"]["cached_count"])
    ]

    max_len = max(len(e[0]) for e in entries)
    for label, fmtfunc in entries:
        padding = " " * (max_len-len(label))
        try:
            print(label+":", padding, fmtfunc(opts, stats))
        except:
            print(label+":", padding, "N/A")

# ------------------------------------------------------------------------------
def clear_stats(log: logging.Logger, opts: ClangTidyCacheOpts) -> None:
    cache = ClangTidyCache(log, opts)
    cache.clear_stats(opts)

# ------------------------------------------------------------------------------
def run_clang_tidy_cached(log: logging.Logger, opts: ClangTidyCacheOpts) -> int:
    cache = ClangTidyCache(log, opts)
    digest = None
    try:
        digest = hash_inputs(log, opts)
        if digest and opts.save_output():
            data = cache.get_cache_data(digest)
            if data is not None:
                returncode = int(data[0])
                sys.stdout.write(data[1:].decode("utf8"))
                return returncode
        elif digest and cache.is_cached(digest):
            return 0
        else:
            pass
    except Exception as error:
        log.error(str(error))

    proc = subprocess.Popen(
        opts.original_args(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    sys.stdout.write(stdout.decode("utf8"))
    sys.stderr.write(stderr.decode("utf8"))

    tidy_success = True
    if proc.returncode != 0:
        tidy_success = False

    if stdout and not opts.ignore_output():
        tidy_success = False

    try:
        clang_format_local = clang_format_cmd.copy()
        clang_format_local.append(opts.original_args()[-1]) 
        subprocess.run(clang_format_local, check=True)
    except subprocess.CalledProcessError:
        log.warning("clang-format failed")

    # saving the result even in case clang-tidy wasn't successful is only meaningful
    # if the output is actually stored. Only then the exit code can be retained
    # (as the first byte in the corresponding key's value)
    save_even_without_success = opts.save_all() and opts.save_output()

    if (tidy_success or save_even_without_success) and digest:
        try:
            if opts.save_output():
                returncode_and_ct_output = bytes([proc.returncode]) + stdout
                cache.store_in_cache_with_data(digest, returncode_and_ct_output)
            else:
                cache.store_in_cache(digest)
        except Exception as error:
            log.error(str(error))

    return proc.returncode

# ------------------------------------------------------------------------------
def main() -> int:
    log = logging.getLogger(os.path.basename(__file__))
    logging.basicConfig(filename="tidyCache.txt", level=logging.DEBUG, format="%(levelname)s:%(message)s")
    log.info("STARTING NEW LOG SESSION")
    debug = False
    opts = None
    try:
        opts = ClangTidyCacheOpts(log, sys.argv[1:])
        debug = opts.debug_enabled()
        if opts.should_print_dir():
            print(opts.cache_dir)
        elif opts.should_remove_dir():
            import shutil
            try:
                shutil.rmtree(opts.cache_dir)
            except FileNotFoundError:
                pass
        elif opts.should_print_stats():
            print_stats(log, opts, False)
        elif opts.should_print_stats_raw():
            print_stats(log, opts, True)
        elif opts.should_zero_stats():
            clear_stats(log, opts)
        else:
            return run_clang_tidy_cached(log, opts)
        return 0
    except Exception as error:
        if debug:
            log.error("Options: %s" % (repr(opts),))
            raise
        else:
            log.error("%s: %s" % (str(type(error)), repr(error)))
        return 1

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())
