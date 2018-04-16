#!/usr/bin/env python

# BSD 3-Clause License

# Copyright (c) 2018, Fabricio Rodriguez, UNICAMP, Brazil
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.

# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.

# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from utils.misc import *
from utils.json2hlir import *

from subprocess import call

import collections

from p4_hlir.main import HLIR
from p4_hlir.hlir import p4_parser
from p4_hlir.hlir import p4_tables

import re
import os
import sys
from os.path import isfile, join

# Possible values are "pragma", "comment" and anything else
#To add line number in generated code
#generate_orig_lines = "comment"
generate_orig_lines = ""
generate_code_files = True
show_code = False

def __init__(self, name):
    self.name = name
    self.p4_code = p4_code

def translate_line_with_insert(file, line_idx, line):
    """Gets a line that contains an insert
       and transforms it to a Python code section."""
    # since Python code is generated, indentation has to be respected
    indentation = re.sub(r'^([ \t]*)#\[.*$', r'\1', line)

    # get the #[ part
    content = re.sub(r'^[ \t]*#\[([ \t]*[^\n]*)[ \t]*', r'\1', line)
    # escape sequences like \n may appear in #[ parts
    content = re.sub(r'\\', r'\\\\', content)
    # quotes may appear in #[ parts
    content = re.sub(r'"', r'\"', content)
    # replace ${var} and ${call()} inserts
    content = re.sub(r'\${([ \t\f\v]*)([^}]+)([ \t\f\v]*)}', r'" + str(\2) + "', content)

    # add a comment that shows where the line is generated at
    is_nonempty_line = bool(content.strip())
    if is_nonempty_line:
        if generate_orig_lines == "comment":
            content += "// line@%d" % (line_idx)
        if generate_orig_lines == "pragma":
            content = '#line %d \\"%s\\"\\n%s' % (line_idx, "../../" + file, content)

    return indentation + "generated_code += \"" + content + "\\n\""


def translate_file_contents(file, code):
    """Returns the code transformed into runnable Python code.
       Translated are #[generated_code and ${var} constructs."""
    has_translateable_comment = re.compile(r'^[ \t]*#\[[ \t]*.*$')

    new_lines = []
    code_lines = code.splitlines()
    for line_idx, code_line in enumerate(code_lines):
        new_line = code_line
        if has_translateable_comment.match(code_line):
            new_line = translate_line_with_insert(file, line_idx+1, code_line)

        new_lines.append(new_line)
    return '\n'.join(new_lines)


def generate_code(file, genfile, localvars={}):
    """The file contains Python code with #[ inserts.
       The comments (which have to be indented properly)
       contain code to be output,
       their contents are collected in the variable generated_code.
       Inside the comments, refer to Python variables as ${variable_name}."""
    with open(file, "r") as orig_file:
        code = orig_file.read()
        code = translate_file_contents(file, code)

        if generate_code_files:
            write_file(genfile, code)

        if show_code:
            print(file + " -------------------------------------------------")
            print(code)
            print(file + " *************************************************")

        localvars['generated_code'] = ""

        #print "Desugaring %s..." % file

        exec(code, localvars, localvars)

        return localvars['generated_code']


def generate_all_in_dir(dir, gendir, outdir, hlir):

    for file in os.listdir(dir):
        full_file = join(dir, file)
        #print full_file
        if not isfile(full_file):
            continue

        if not full_file.endswith(".generator.py"):
            continue

        genfile = join(gendir, re.sub(r'\.(generator)\.py$', r'.\1.desugared.py', file))
        #print genfile
        code = generate_code(full_file, genfile, {'hlir': hlir})

        outfile = join(outdir, re.sub(r'\.(generator)\.py$', r'', file))

        write_file(outfile, code)


def make_dirs(compiler_files_path, desugared_path, generated_path):
    """Makes directories if they do not exist"""
    if not os.path.isdir(compiler_files_path):
        #print("Compiler files path is missing")
        sys.exit(1)

    if not os.path.isdir(desugared_path):
        os.makedirs(desugared_path)
        #print("Generating path for desugared compiler files: {0}".format(desugared_path))

    if not os.path.isdir(generated_path):
        os.makedirs(generated_path)
        #print("Generating path for generated files: {0}".format(generated_path))


def setup_paths(p4_code):
    """Gets paths from the command line arguments (or defaults)
       and makes sure that they exist in the file system."""
    argidx_p4, argidx_genpath, argidx_srcpath = 1, 2, 3

    #p4_path = sys.argv[argidx_p4]
    p4_path = p4_code
    #compiler_files_path = sys.argv[argidx_srcpath] if len(sys.argv) > argidx_srcpath else join("src", "p4_support")
    compiler_files_path = join("src", "p4_support")
    #print compiler_files_path
    desugared_path = join("build", "util", "desugared_compiler")
    #print desugared_path
    generated_path = join("build", "src_p4_support")
    #print generated_path
    #generated_path = sys.argv[argidx_genpath] if len(sys.argv) > argidx_genpath else join("output", "src_hardware_indep")

    make_dirs(compiler_files_path, desugared_path, generated_path)

    return p4_path, compiler_files_path, desugared_path, generated_path


def write_file(filename, text):
    """Writes the given text to the given file with optional beautification."""
    with open(filename, "w") as genfile:
        genfile.write(text)


class run_transpiler:

    def __init__(self, name):
        self.pkts = []

    def principal(self, p4_code):
        
        #print "Transpiler started"

        # if len(sys.argv) <= 1:
        #     print("Usage: %s p4_file [compiler_files_dir] [generated_dir]" % (os.path.basename(__file__)))
        #     sys.exit(1)

        filepath, compiler_files_path, desugared_path, generated_path = setup_paths(p4_code)

        # if p4_code is False:
        #     print("FILE NOT FOUND: %s" % filepath)
        #     sys.exit(1)

        _, ext = os.path.splitext(filepath)
        if ext == '.p4':
            hlir = HLIR(filepath)
            success = build_hlir(hlir)
        # elif ext == '.json':
        #     hlir = json2hlir(filepath)
        #     success = True
        else:
            print("EXTENSION NOT SUPPORTED: %s" % ext)
            sys.exit(1)

        if not success:
            print("Transpiler failed for use-case %s" % (os.path.basename(__file__)))
            sys.exit(1)

        generate_all_in_dir(compiler_files_path, desugared_path, generated_path, hlir)

        showErrors()
        showWarnings()

     #    global errors
     #    if len(errors) > 0:
    	# sys.exit(1)


    #principal("","")
