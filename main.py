import argparse
import os
from obfuscate import obfuscate
from deobfuscate import process

def main():
    parser = argparse.ArgumentParser(prog='Obfuscator & DeObfuscator', description='Obfuscate and DeObfuscate your code')
    subparsers = parser.add_subparsers(dest='mode', help='Choose the mode of operation: obfuscate or deobfuscate')
    
    obfuscate_parser = subparsers.add_parser('obfuscate', help='Obfuscate your code')
    obfuscate_parser.add_argument('file', help='Input file to obfuscate')

    deobfuscate_parser = subparsers.add_parser('deobfuscate', help='DeObfuscate your code')
    deobfuscate_parser.add_argument('file', help='Input file to deobfuscate')

    args=parser.parse_args()


    if args.mode == 'obfuscate':
        obfuscator.process(args.file)
    elif args.mode == 'deobfuscate':
        deobfuscate_process(args.file)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()        