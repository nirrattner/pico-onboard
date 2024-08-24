#!/usr/bin/env python3

import os
import re
import struct

import c2py

CURRENT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
INPUT_HEADER_FILE = CURRENT_DIRECTORY + '/../network_interface.h'

START_PATTERN = re.compile('(typedef enum|typedef struct) {')
END_PATTERN = re.compile('} (.*)_t;')

PACK_FORMAT = '<'

class CommandProtocolStructInstance:
  def __init__(self, definition):
    self.definition = definition
    self.size = definition['size']
    buffer = b'\00' * self.size
    self.fields = c2py.depack_bytearray_to_dict(buffer, self.definition['text'], PACK_FORMAT)

  def pack(self):
    variables = []
    pack_format = self.definition['pack_format']
    variable_list = self.definition['variable_list']

    for variable_name, array_length in variable_list:
      if array_length > 1:
        variables.append(self.fields[variable_name])
        if array_length > len(self.fields[variable_name]):
          variables += '\0' * (array_length - len(self.fields[variable_name]))
      else:
        variables.append(self.fields[variable_name])

    for index in range(len(variables)):
      if pack_format[index + 1] == 'c' and isinstance(variables[index], int):
        variables[index] = ('%c' % variables[index]).encode()
      elif isinstance(variables[index], str):
        variables[index] = variables[index].encode()
    buffer = struct.pack(pack_format, *variables)

    return buffer

  def unpack(self, input_data):
    self.fields = c2py.depack_bytearray_to_dict(input_data, self.definition['text'], PACK_FORMAT)

class CommandProtocol:
  def __init__(self):
    # TODO: Parse version from header
    self.version = 1
    self.definitions = {}
    with open(INPUT_HEADER_FILE, 'r') as input_file:
      lines = []
      for line in input_file.readlines():
        result = START_PATTERN.search(line)
        if result:
          if result.group(1) == 'typedef enum':
              kind = 'enum'
          else:
              kind = 'struct'
          lines = []
        line = line.split('//')[0].strip()
        if line:
          lines.append(line)

        result = END_PATTERN.search(line)
        if result:
          name = result.group(1)
          text = '\n'.join(lines)
          if kind == 'struct':
            size = c2py.structSize(text, PACK_FORMAT)
            variable_list, pack_format = c2py.structInfo(text, PACK_FORMAT)
          elif kind == 'enum':
            size = 0
            pack_format = None
            entries = [re.sub('[ ,\n]', '', value) for value in lines[1:-1]]

            next_value = 0
            variable_list = {}
            for entry in entries:
              entry_splits = entry.split('=')
              if len(entry_splits) > 1:
                next_value = eval(entry_splits[1])
              variable_list[entry_splits[0]] = next_value
              next_value += 1

          self.definitions[name] = dict(
              pack_format=pack_format,
              variable_list=variable_list,
              size=size,
              text=text)

  def allocate(self, type):
    return CommandProtocolStructInstance(self.definitions[type])

  def enum(self, type, value):
    return self.definitions[type.lower()]['variable_list'][type.upper() + '__' + value.upper()]

  def enum_name(self, type, value):
    for enum_name, enum_value in self.definitions[type.lower()]['variable_list'].items():
      if enum_value == value:
        return enum_name.lower().split('__')[1]

if __name__ == '__main__':
  protocol = CommandProtocol()
  command = protocol.allocate('request')
  command.fields['type'] = protocol.enum('request_type', 'ping')
  print(command.pack())

  print(protocol.enum_name('request_type', 1))

