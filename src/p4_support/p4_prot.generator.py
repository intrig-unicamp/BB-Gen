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

import p4_hlir.hlir.p4 as p4
from p4_hlir.hlir.p4_sized_integer import *
from p4_hlir.hlir.p4_headers import *
from p4_hlir.hlir.p4_imperatives import p4_signature_ref
from src.p4_support.utils.hlir import *
from src.p4_support.utils.misc import addError, addWarning
import math

import src.settings

#[//ERFS file Created!!

OfPorts = {100:"ALL", 200:"CONTROLLER"}
unkwnPrimtv = 0
drpPrimtv = 0

ofCmd=""

header_lenght = []
header_value = []


#[//Header Details:-
for header_val in hlir.p4_headers.values():
    #["${header_val.name}"
    #["${header_val.attributes}"
    #["${header_val.length}"
    #header_len  =  ','.join([str(hn) for hn in header_val.layout.values()])
    for hn in header_val.layout.values():
        header_lenght.append(str(hn))
    ##[      Header length = ${header_len}
    #[      Header length = ${header_lenght}
    #header_valo  =  ','.join([str(hn) for hn in header_val.layout.keys()])
    for hn in header_val.layout.keys():
        header_value.append(str(hn))   
    ##[      Header value = ${header_valo}
    #[      Header value = ${header_value}
    
    src.settings.header_list_len.append(list(header_lenght))
    src.settings.header_list_val.append(list(header_value))

    del header_lenght[:]
    del header_value[:]
#[

#[//Header Details 2:-
for header_val in hlir.p4_header_instances.values():
    #["${header_val.name}"
    #["${header_val.header_type}"
    #["${header_val.metadata}"
    #["${header_val.virtual}"
#[

#[//Table Details:-
for table in hlir.p4_tables.values():
    table_type, key_length = getTypeAndLength(table)
    #["${table.name}"
    #["${table.match_fields}"
    matchFields  =  ','.join([str(fld.name) for fld, tp, msk in table.match_fields])
    #[      Match Fields = ${matchFields}
    #["${table.actions}"
    actionList  =  ','.join([str(act.name) for act in table.actions])
    #[      Action List = ${actionList}
#[

def cmd_select():
    return "add"

cmdTypeList = ["flow-mod"]
def cmd_type_select():
    return cmdTypeList[0]

def tbl_select(name):
    tableList = [table.name for table in hlir.p4_tables.values()]
#    #[Table list is: ${tableList}
    return tableList.index(name)

def format_p4_node(node):
    if node is None:
        return " "
    elif isinstance(node, p4.p4_table):
#        return "goto:%s" % node.name
        return "goto:%s" % tbl_select(node.name)
    elif isinstance(node, p4.p4_conditional_node):
        #[//table_next_ conditional node not supported
        addWarning("generating modify_field", "field '" + str(dst.name) + "' not supported")
        return "0"
        #return "if (%s) { %s } else { %s }" % (format_expr(node.condition), format_p4_node(node.next_[True]), format_p4_node(node.next_[False]))


# =============================================================================
# DROP
def drop(fun, call):
#    return generated_code;
    global drpPrimtv
    drpPrimtv = 1
    return "clear:"

# =============================================================================
# GENERATE_DIGEST
def generate_digest(fun, call):
    extracted_params = []
    for p in call[1]:
        if isinstance(p, int):
            extracted_params += "0" #[str(p)]
        elif isinstance(p, p4_field_list):
            field_list = p
            extracted_params += ["&fields"]
        else:
            addError("generating prfs.sh", "Unhandled parameter type in generate_digest: " + str(p))
    #return generated_code
    return "output=CONTROLLER"

actHdrList = ["vlan"]
actFieldList = ["eth_dst","eth_src","eth_type"]
actFieldExpList = {"egress_port":"output"}

# ========================================================================
# ADD_HEADER
def add_header(fun, call):
    generated_code = ""
    args = call[1]
    hdrInst = args[0]
    if len(args)>1:
        addError("generating add_header", "Unsupported number of args")
    if not isinstance(hdrInst, p4_header_instance):
        addError("generating add_header", "need header_instance as arg")
    if hdrInst.name not in actHdrList:
        addWarning("generating add_header", "header '" + str(hdrInst.name) + "' not supported")
        global unkwnPrimtv
        unkwnPrimtv = 1
        return fun.name
    return "push_vlan"

# ========================================================================
# REMOVE_HEADER
def remove_header(fun, call):
    generated_code = ""
    args = call[1]
    hdrInst = args[0]
    if len(args)>1:
        addError("generating remove_header", "Unsupported number of args")
    if not isinstance(hdrInst, p4_header_instance):
        addError("generating remove_header", "need header instance as args")
    if hdrInst.name not in actHdrList:
        addWarning("generating remove_header", "header '" + str(hdrInst.name) + "' not supported")
        global unkwnPrimtv
        unkwnPrimtv = 1
        return fun.name
    return "pop_vlan"

# ========================================================================
# MODIFY_FIELD
def modify_field(fun, call):
    actName = "set_field"
    generated_code = ""
    args = call[1]
    dst = args[0]
    src = args[1]
    mask = ''
    if len(args)==3:
        addError("generating modify_field", "Mask not supported")
    if not isinstance(dst, p4_field):
        addError("generating modify_field", "We do not allow changing an R-REF yet")
    #prfs code
    if is_vwf(dst):
        addError("generating modify_field", "variable width field not supported")
    if dst.name in actFieldExpList.keys():
        #[//egress port presetn
        if isinstance(src, int):
            if src in OfPorts.keys():
                return actFieldExpList[dst.name]+"="+OfPorts[src]
        return actFieldExpList[dst.name]+"="
    if dst.name not in actFieldList:
        addWarning("generating modify_field", "field '" + str(dst.name) + "' not supported")
        global unkwnPrimtv
        unkwnPrimtv = 1
        return fun.name
    return actName+"="+dst.name+":"

#==================================================
#dpctl connection cmd_type table,cmd,prio match_fields instructin:actions

#[Example of a DPCTL rule:-
#[//$d $s flow-mod table=0,cmd=add,prio=12 in_port=2 apply:output=2
#[

#Set dpctl
#d="/home/ethmola/bin/dpctl"
d="$1"
#Set Of connection details
s="$2"
#s="tcp:localhost:16633"
ofCmd = ofCmd + d + " " + s + " "

#Set OF command type
cmdType = cmd_type_select()
ofCmd = ofCmd + cmdType + " "
ofCmdDef = ofCmd

#table, cmd, prio
#set cmd
CMD = cmd_select()

#Set Priority
ofPrio = 10

# for table in hlir.p4_tables.values():
#     #[
#     #[//For Table : ${table.name} ${tbl_select(table.name)}
#     #[
#     tblId = tbl_select(table.name)

# #set table, cmd, prio
#     ofCmd = ofCmd + ','.join(("table="+str(tblId),"cmd="+CMD,"prio="+str(ofPrio)))+" "

# #Set match fields
#     matchFields  =  ','.join([str(fld.name) for fld, tp, msk in table.match_fields])
#     ofCmd = ofCmd + matchFields + " "

#     tblName = tbl_select(table.name)
#     actionList = []
#     actionListFlag = 0

#     ofCmdTemp = ofCmd

#     if 'hit' in table.next_:
#         if table.next_['hit'] is not None:
#             ofCmd = ofCmd + format_p4_node(table.next_['hit'])
#             #[${ofCmd}
#             ofCmd = ofCmdTemp
#         if table.next_['miss'] is not None:
#             ofCmd = ofCmd + format_p4_node(table.next_['miss'])
#             #[${ofCmd}
#             ofCmd = ofCmdTemp
#     else:
#         for action, nextnode in table.next_.items():
# #            #[${table.name} -> ${nextnode}
#             if action.name == "drop":
#                 ofCmd = ofCmd + "clear:"
#                 #[${ofCmd}
#             elif action.name != "_nop":
#                 if not primitive(action):
#                     hasParam = action.signature
#                     modifiers = ""
#                     ret_val_type = "void"
#                     name = action.name
#                     for i,call in enumerate(action.call_sequence):
#                         ##[${i} + ${call}
#                         name = call[0].name
#                         # Generates a primitive action call to `name'
#                         # locals() returns a dictionary of current namesapce
#                         if name in locals().keys():
# #                            #[locals ${name}
#                             aName = locals()[name](action, call)
# #                           #[local return ${aName}
#                             actionList.append(aName)
#                             actionListFlag = 1
# #                            #[unkwnPrimtv is ${unkwnPrimtv}, ${aName}
#                             if unkwnPrimtv:
#                                 unkwnPrimtv = 0
#                                 break
#                         else:
#                             addWarning("generating prfs","Unhandled primitive function: " +  name)
#                 if drpPrimtv:
#                     drpPrimtv = 0
#                     ofCmd = ofCmd + "clear:"
#                     #[${ofCmd}
#                     ofCmd = ofCmdTemp
#                 elif actionListFlag:
#                     actionListString = ",".join(actionList)
#                     ofCmd = ofCmd + "apply:"+ actionListString + " " + format_p4_node(nextnode)
#                     #[${ofCmd}
#                     ofCmd = ofCmdTemp
#                     actionListFlag = 0
#                     actionList = []
#                 else:
#                     ofCmd = ofCmd + "apply:"+ action.name + " " + format_p4_node(nextnode)
#                     #[${ofCmd}
#                     ofCmd = ofCmdTemp
#     ofCmd = ofCmdDef
# #for condP4 in hlir.p4_conditional_nodes.values():
# #    #[${condP4.condition}
# #    #[${condP4.next_}
# #[
