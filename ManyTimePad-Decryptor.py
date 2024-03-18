# Created by Jose Carpio
# This program attempts to decrypt a target cipher using XOR analysis and cribb dragging given other ciphertexts encrypted with the same key.
# 1. Attempts to decrypt by XORing and analyzing character frequencies.
# 2. Using the attempted decryption cribb dragg and guess the possible plaintext and save the key fragments. 
# 3. Decrypt all ciphers using the last known or guessed key fragments.

import collections  #useful for tallying occurrences of elements, such as calculating the frequency of characters in ciphertexts
from binascii import unhexlify, hexlify #module contains methods for converting between binary and various ASCII-encoded binary representations
import re #regular expression matching operations

# XOR two byte arrays
def strxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

#Identify likely space positions by XORing and analyzing character frequencies.
def xor_analysis(ciphers):
    #checks if the ciphers list is empty
    if not ciphers:
        return []
    #finds the minimum lenght of all ciphers
    min_length = min(len(c) for c in ciphers) 
    #initialize a list of objects, one for each byte position up to the length of the shortest cipher
    space_scores = [collections.Counter() for _ in range(min_length)]
    #nested loop for XOR operatrions
    for i, c1 in enumerate(ciphers):
        for j, c2 in enumerate(ciphers[i + 1:], start=i + 1):
            xor_result = strxor(c1[:min_length], c2[:min_length])
            for k, byte in enumerate(xor_result):
                #check it's an alphabetical character
                if chr(byte).isalpha():
                    space_scores[k].update([i, j])
    return space_scores

#Attempt decryption assuming identified spaces and common characters.
def decrypt_with_spaces(ciphers, space_scores):
    # Find the minimum length among all ciphers to ensure uniform processing
    min_length = min(len(c) for c in ciphers)
    
    # Initialize a bytearray for the guessed key, with the same length as the shortest cipher
    key_guess = bytearray(min_length)
    
    # Iterate over each byte position in the space_scores list
    for i, counter in enumerate(space_scores):
        # Check if the counter for the current byte position has any elements
        if counter:  
            # Find the cipher text index that is most commonly associated with a space at this position
            index, _ = counter.most_common(1)[0]
            
            # Guess the key byte for this position:
            # XOR the byte from the cipher text (most likely to be XOR'ed with a space) with the ASCII value of space
            # This operation is based on the property that if A XOR B = C, then C XOR B = A or C XOR A = B
            key_guess[i] = ciphers[index][i] ^ ord(' ')
    
    # After iterating through all positions, return the guessed key as a bytearray
    return key_guess

def is_readable(text):
    #Check if the text is readable: consisting of printable characters, spaces, or common punctuation
    return bool(re.match(r'^[\x20-\x7E\s]+$', text))

def crib_drag(ciphers, target_cipher, saved_key_fragments=None):
    # Initialize saved key fragments dictionary if not provided
    if saved_key_fragments is None:
        saved_key_fragments = {}
    
    # Prompt the user to enter a crib (a known or guessed part of the plaintext)
    crib = input("Enter your crib: ").strip()
    # Convert the crib into bytes for XOR operations
    crib_bytes = crib.encode()
    # Initialize a list to hold potential matches
    potential_matches = []
    
    # Iterate over each possible starting position of the crib in the target cipher
    for index in range(len(target_cipher) - len(crib_bytes) + 1):
        # XOR the part of the target cipher with the crib to get a mask (potential key fragment)
        mask = strxor(target_cipher[index:index+len(crib_bytes)], crib_bytes)
        # Iterate over all ciphers to apply the mask
        for cipher_index, cipher in enumerate(ciphers):
            # Skip if the crib goes beyond the cipher's length
            if index + len(crib_bytes) > len(cipher):
                continue
            # Apply the mask to the current cipher at the current position
            dragged = strxor(cipher[index:index+len(crib_bytes)], mask)
            # Try to decode the result as ASCII, ignoring errors
            dragged_text = dragged.decode('ascii', errors='ignore')
            # Check if the result is readable (using a custom function not provided here)
            if is_readable(dragged_text):
                # If readable, add the match to potential matches
                potential_matches.append({
                    'position': index,
                    'cipher_index': cipher_index,
                    'key_fragment': hexlify(mask).decode(),
                    'text': dragged_text
                })
                
    # Display potential matches to the user
    for i, match in enumerate(potential_matches):
        print(f"{i}: Position {match['position']} in Cipher {match['cipher_index']}: {match['text']}")
    
    # If there are any matches, allow the user to select one to save
    if potential_matches:
        while True:  # Keep asking until a valid response is given or the user chooses to skip
            selection = input("Enter the number of the match to save for further crib dragging, or 'skip' to skip: ").strip().lower()
        
            # Process the user's selection
            if selection.isdigit():
                selected_index = int(selection)
                # Validate the selection is within range
                if 0 <= selected_index < len(potential_matches):
                    selected_match = potential_matches[selected_index]
                    # Save the selected key fragment along with its position and cipher index
                    saved_key_fragments[(selected_match['position'], selected_match['cipher_index'])] = selected_match['key_fragment']
                    print(f"Saved Key Fragment: {selected_match['key_fragment']} at Position {selected_match['position']} in Cipher {selected_match['cipher_index']}")
                    break  # Exit the loop after a valid selection
                else:
                    print("Invalid selection. Please try again.")
            elif selection == 'skip':
                print("Skipping. No changes made.")
                break  # Exit the loop if skipping
            else:
                print("Invalid input. Please enter a valid number or 'skip'.")
    else:
        # Notify the user if no readable matches were found
        print("No readable matches found.")
        
    # Return the dictionary of saved key fragments for further analysis
    return saved_key_fragments

    
def decrypt_with_last_key_fragment(ciphers, saved_key_fragments):
    decrypted_texts = []
    
    # Retrieve the last saved key fragment and its position
    if saved_key_fragments:
        last_position, last_index = max(saved_key_fragments.keys(), key=lambda x: (x[1], x[0]))
        last_key_fragment = saved_key_fragments[(last_position, last_index)]
        last_key_fragment_bytes = unhexlify(last_key_fragment)
    else:
        print("No saved key fragments to apply.")
        return []

    for cipher in ciphers:
        # Initialize a bytearray for decrypted text with the same length as the cipher
        decrypted_text = bytearray(len(cipher))
        start = last_position
        end = start + len(last_key_fragment_bytes)

        # Apply the last key fragment to each cipher text
        for i in range(start, min(end, len(cipher))):
            decrypted_text[i] = cipher[i] ^ last_key_fragment_bytes[i - start]

        # Attempt to decode the resulting bytearray
        decrypted_texts.append(decrypted_text.decode('ascii', errors='ignore'))

    return decrypted_texts

#Main function 
def main():
    print("Many Time Pad  Decryption\n")
    # Placeholder for ciphertexts setup
    ciphers_hex = [
        "71fe1ace4389087266117cd7c98c4182851b3acff3b086e3f83f94d6eb05c4ba85d8e1fa14f11d1c3b568ff6cff5c09c5d67ef5c9c71b7eeb3d45a5154ab17b83e071ce9d8988adb4afedf46a840",
        "71fe1ace559a1e7266117cd7ce8745d7be2e74c3f0f68eeef57e8884e607debf81dfa0f012f95819681ae7f29fe4839b5175ef5e8760bef0b9d44b504eba12b22f5404f89dd085d550a48865a14f9b15a94dabe609ca2df2cccf210cefdb1af5389719795e1f0179cb77c5c456954d88f3",
        "72fe069c51c81a20775928c7879d4fd2a93c3acff3f69fe5fe2e9493a303d9ea98c4e5b60ae40a146058e7c787fbd09a1474e25dc865b5e6af865d4a40a61bfd384e06e0cfc1ccd356ff8853ac438905fa5fe3fd41cb3bbc8ac9",
        "67e543885b9a5b2267177084cf8453ccb8633ad7fdb39de5b13f8a93a304d6bf8bc4f4ef5def110b6f56a3e186e2c68c1470ef5c9c2ffbd6a291571e40ba1afd3b4b1fe0c4cbccc15df5dc07b043da01fa6ae4fd158f37b3c0cd",
        "71fe029a148c1236320d7192878a59cfbc3a6ec5e7f68befb13196d6ea1ec4ea81d9e3fe50ea0f196d02a2f7cfe2c29c5577e35d8630baf6ea80465b01aa1abc394f57a1f4ccccda59ff8846e44b8805bb5cabe608c231f2dec8364ae7d90ab4358c5c3a421b06",
        "6ef914ce5989152b321a769ad79c42c7be6f6ad2fab19de1fc339d84f04ad3a589dfa0ff09ab0c196f13e7e780b4c097556ded57c871fbeea393464a01aa0ab1381848cfd2d6898918efc046b00b8940bb08e3f313cb23b3dfd8645cfcd80ff82489",
        "71fe1ace4389087266117cd7c4865bd2b93b7fd2b5a58ce9f4308c9ff01e97ab82cbf2ef5dfc101d6a56b3fb8ab4d08b4167ef5c9c30b8f0ab97455b45e81efd364605e49ddb83df48eedc42b60c900fb14db4b229ca74b6c4d96442e1c34df8288f5c3a450a527ecc7c82865b8e",
        "71fe029a148c1437615978d7c58854dbec2c75cde5a39be5e37e9b97ef0697a285dfa0f01cff101d764983f29bf5",
        "71fe1ace50875b31730d6ad7cb8640c7ec3c73d4e1bf81e7b13796d6e518d8a4988ceff05dff101d2415a8fe9fe1d79a4623eb5e8430bfe3b3d442514faf40fd18420be0c8cb89924cf3cd5ee448950efd5cabe500c120f2d9d26440ebc34de029811977430b01748276d79012955cc6a65aebb9054becda5c9278",
        "71fe029a1483123c76597691878459cca9363ac4faf68ceffc2e8d82e61897b98fc5e5f809e20b0c7756b2e08aab83bc5560e257",
                ]
    target_cipher_hex = "71fe0680149d083b7c1e3996879a42d0a92e7780f6bf9fe8f42cd898e61cd2b8ccd9f3f35dff101d241da2eacff9cc8d5123fe5a897efbeda4974b"

    #iterate over each hex-encoded string in the list converting the hex string into its binary representation 
    ciphers = [unhexlify(c) for c in ciphers_hex]
    # converting the hex string into its binary representation
    target_cipher = unhexlify(target_cipher_hex)

    # Infinite loop to continuously offer the user a set of options for interacting with the program.
    while True:
        # Printing the menu options for the user.
        print("\nOptions:")
        print("1. Show possible decrypted target cipher")
        print("2. Perform crib dragging")
        print("3. Decrypt")
        print("4. Exit")
        # Prompting the user to choose an option.
        choice = input("Choose an option: ")

        # Handling the user's choice.
        if choice == '1':
            # Option 1: Attempt to decrypt the target cipher based on XOR analysis and key guessing.
            # Perform XOR analysis to identify potential space positions in the ciphertext.
            space_scores = xor_analysis(ciphers)
            # Attempt to guess the key based on the analysis.
            key_guess = decrypt_with_spaces(ciphers, space_scores)
            # Decrypt the target cipher with the guessed key and display the result.
            decrypted_target = strxor(target_cipher, key_guess[:len(target_cipher)])
            print("Decrypted Target Cipher:", decrypted_target.decode('ascii', errors='replace'))
            print("Guessed Key:", hexlify(key_guess).decode())
        elif choice == '2':
            # Option 2: Perform crib dragging to potentially reveal more of the key or plaintext.
            if 'target_cipher' in locals():
                # Perform crib dragging if the target cipher is defined, potentially updating saved key fragments.
                saved_key_fragments = crib_drag(ciphers, target_cipher)      
            else:
                # Error message if no target cipher has been defined.
                print("No target cipher defined.")
        elif choice == '3':
            # Option 3: Decrypt all ciphers using the last known or guessed key fragments.
            decrypted_texts = decrypt_with_last_key_fragment(ciphers, saved_key_fragments)
            # Display the decrypted texts.
            for text in decrypted_texts:
                    print(text)
        elif choice == "4":
            # Option 4: Exit the program.
            print("Exiting...")
            break
        else:
            # Handling invalid input by notifying the user and looping back to the menu.
            print("Incorrect selection")

# Main function guard to ensure this code runs only when the script is executed directly, not when imported.
if __name__ == "__main__":
    main()