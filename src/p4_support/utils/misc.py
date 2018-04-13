# Miscellaneous utility functions (not using HLIR)

import sys
import os

errors = []

warnings = []

def addError(where, msg):
    global errors
    errors += ["ERROR: " + msg + " (While " + where + ").\n"]

def addWarning(where, msg):
    global warnings
    warnings += ["WARNING: " + msg + " (While " + where + ").\n"]

def showErrors():
   global errors
   for e in errors: print e

def showWarnings():
   global warnings
   for w in warnings: print w

disable_hlir_messages = False

def build_hlir(hlir):
    """Builds the P4 internal representation, optionally disabling its output messages.
    Returns True on success"""
    if disable_hlir_messages:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')

    success = hlir.build()

    if disable_hlir_messages:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return success
