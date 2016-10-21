#!/usr/bin/python

def load_class_insts(class_inst_list_file):
  with open(class_inst_list_file, 'r') as f:
    data = f.readlines()
  for i in range(len(data)):
    data[i] = data[i].strip()
  return data
    

if __name__ == '__main__':
  class_inst_list_file = "./class_inst_list"
  class_insts = load_class_insts(class_inst_list_file)
  for i in range(len(class_insts)):
    name = class_insts[i].upper()
    print '    INST_%s = 0x%02x,' % (name, i)
  for inst in class_insts:
    enum_name = 'INST_%s' % inst.upper()
    print '    {%s, "%s"},' % (enum_name, inst)