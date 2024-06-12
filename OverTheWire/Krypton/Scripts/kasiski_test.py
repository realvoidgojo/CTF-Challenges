from collections import defaultdict
import re
import sys
from math import gcd
from collections import Counter

def kasiski_test(ciphertext):
    # Remove non-alphabet characters and convert to uppercase
    ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
    
    # Dictionary to store sequences and their positions
    sequences = defaultdict(list)
    
    # Look for sequences of 3 characters (can be adjusted if needed)
    for i in range(len(ciphertext) - 2):
        seq = ciphertext[i:i+3]
        sequences[seq].append(i)
    
    # Find distances between repeated sequences
    distances = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                distances.append(positions[i] - positions[i-1])
    
    # Calculate GCD of each pair of distances and count frequencies
    gcd_counts = Counter()
    for i in range(len(distances)):
        for j in range(i + 1, len(distances)):
            g = gcd(distances[i], distances[j])
            if g > 1:  # We are interested in GCDs greater than 1
                gcd_counts[g] += 1
    
    return gcd_counts

def main():
    # Check if the file path argument is provided
    if len(sys.argv) != 2:
        print("Usage: python kasiski.py <ciphertext_file>")
        return

    # Read ciphertext from file
    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as file:
            ciphertext = file.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return
    
    # Perform Kasiski test to find the key length frequencies
    gcd_counts = kasiski_test(ciphertext)
    
    if gcd_counts:
        # Calculate total counts
        total_counts = sum(gcd_counts.values())
        
        # Print frequencies as percentages
        print("Possible key lengths with likelihood percentages:")
        for key_length, count in gcd_counts.most_common():
            percentage = (count / total_counts) * 100
            if percentage < 1:
                break
            print(f"{key_length} -> {percentage:.2f}%")
    else:
        print("No repeated sequences found. Unable to estimate key length.")

if __name__ == "__main__":
    main()
