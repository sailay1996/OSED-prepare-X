#!/usr/bin/python
import numpy, sys  # Importing necessary libraries: numpy for binary representation and sys for command-line arguments

# Function to perform a bitwise "rotate right" operation on a 32-bit integer
def ror_str(byte, count):
    # Convert the byte to a binary string, padded to 32 bits
    binb = numpy.base_repr(byte, 2).zfill(32)
    # Rotate the binary string to the right by `count` positions
    while count > 0:
        binb = binb[-1] + binb[0:-1]  # Move the last bit to the front, shifting the rest to the right
        count -= 1  # Decrease the count until no more rotations are required
    return int(binb, 2)  # Convert the rotated binary string back to an integer

# Main execution
if __name__ == '__main__':
    try:
        # Try to retrieve the input string from command-line arguments
        esi = sys.argv[1]
    except IndexError:
        # If no argument is provided, print usage and exit
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    # Initialize variables
    edx = 0x00  # Accumulator for result (initially set to 0)
    ror_count = 0  # Counter to control the rotate-right operation frequency

    # Loop through each character in the input string (`esi`)
    for eax in esi:
        edx = edx + ord(eax)  # Add the ASCII value of each character to `edx`
        # Perform rotate-right on `edx` by 13 bits if this is not the last character
        if ror_count < len(esi) - 1:
            edx = ror_str(edx, 0xd)  # Rotate right by 13 bits (0xd in hex)
        ror_count += 1  # Increment the rotate count for each character

    # Print the final value of `edx` in hexadecimal format
    print(hex(edx))
