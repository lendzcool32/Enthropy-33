# filepath: puzzle_kit/custom_vm.py
import sys

class VirtualMachine:
    """
    A secure, custom stack-based Virtual Machine.
    """
    def __init__(self, bytecode):
        self.bytecode = bytearray(bytecode)
        self.stack = []
        self.pc = 0
        self.acc = 0
        self.stdout = []
        self.input_buffer = []

        self.opcodes = {
            0x01: self.op_push,  # PUSH <val: 4 bytes>
            0x02: self.op_pop,   # POP
            0x03: self.op_add,   # ADD
            0x04: self.op_sub,   # SUB
            0x05: self.op_xor,   # XOR
            0x06: self.op_jz,    # JZ <addr: 2 bytes>
            0x07: self.op_jmp,   # JMP <addr: 2 bytes>
            0x08: self.op_out,   # OUT
            0x09: self.op_halt,  # HALT
            0x0A: self.op_in     # IN
        }

    def run(self, user_input=""):
        self.input_buffer = list(user_input)
        self.pc = 0
        self.stack = []
        self.stdout = []
        
        while self.pc < len(self.bytecode):
            opcode = self.bytecode[self.pc]
            if opcode in self.opcodes:
                self.pc += 1
                self.opcodes[opcode]()
                if opcode == 0x09: # HALT
                    break
            else:
                raise ValueError(f"Unknown Opcode {opcode:02X} at PC {self.pc}")
        return "".join(self.stdout)

    def op_push(self):
        val = int.from_bytes(self.bytecode[self.pc:self.pc+4], "big", signed=True)
        self.stack.append(val)
        self.pc += 4

    def op_pop(self):
        self.acc = self.stack.pop()

    def op_add(self):
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append((b + a) & 0xFFFFFFFF)

    def op_sub(self):
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append((b - a) & 0xFFFFFFFF)

    def op_xor(self):
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(b ^ a)

    def op_jz(self):
        addr = int.from_bytes(self.bytecode[self.pc:self.pc+2], "big")
        self.pc += 2
        val = self.stack.pop()
        if val == 0:
            self.pc = addr

    def op_jmp(self):
        addr = int.from_bytes(self.bytecode[self.pc:self.pc+2], "big")
        self.pc = addr

    def op_out(self):
        val = self.stack.pop()
        self.stdout.append(chr(val & 0xFF))

    def op_halt(self):
        pass

    def op_in(self):
        if self.input_buffer:
            char = self.input_buffer.pop(0)
            self.stack.append(ord(char))
        else:
            self.stack.append(0) # EOF

def assemble(asm_text):
    """
    Assemble an assembly program into the custom bytecode.
    """
    opcodes = {
        "PUSH": 0x01, "POP": 0x02, "ADD": 0x03, "SUB": 0x04,
        "XOR": 0x05, "JZ": 0x06, "JMP": 0x07, "OUT": 0x08,
        "HALT": 0x09, "IN": 0x0A
    }
    labels = {}
    lines = [line.strip().split(";")[0] for line in asm_text.splitlines()]
    lines = [line for line in lines if line]

    # Pass 1: find label addresses
    address = 0
    clean_instructions = []
    for line in lines:
        if line.endswith(":"):
            labels[line[:-1]] = address
        else:
            clean_instructions.append(line)
            parts = line.split()
            op = parts[0]
            address += 1
            if op == "PUSH":
                address += 4
            elif op in ("JZ", "JMP"):
                address += 2

    # Pass 2: generate bytecode
    bytecode = bytearray()
    for line in clean_instructions:
        parts = line.split()
        op = parts[0]
        bytecode.append(opcodes[op])
        if op == "PUSH":
            val = int(parts[1])
            bytecode.extend(val.to_bytes(4, "big", signed=True if val < 0 else False))
        elif op in ("JZ", "JMP"):
            lbl = parts[1]
            target_addr = labels[lbl]
            bytecode.extend(target_addr.to_bytes(2, "big"))

    return bytes(bytecode)

if __name__ == "__main__":
    print("[*] Running VM Assembler & Interpreter Self-Test...")
    asm = """
    IN
    PUSH 51
    XOR
    JZ char_ok
    PUSH 70
    OUT
    HALT
    char_ok:
    PUSH 80
    OUT
    HALT
    """
    bytecode = assemble(asm)
    vm = VirtualMachine(bytecode)
    
    out1 = vm.run("a")
    assert out1 == "F", f"VM failure test failed: expected F, got {out1}"
    
    out2 = vm.run("3")
    assert out2 == "P", f"VM pass test failed: expected P, got {out2}"
    print("[+] VM Self-Test Passed!")
