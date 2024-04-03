import sys
from BitVector import *

class AES():
    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__ ( self , keyfile :str ) -> None :
    # encrypt - method performs AES encryption on the plaintext
    #and writes the ciphertext to disk
    # Inputs : plaintext (str) - filename containing plaintext
    # ciphertext (str) - filename containing ciphertext
    # Return : void
        
        self.AES_modulus = BitVector(bitstring='100011011')
        self.subBytesTable = []                                                  # for encryption
        self.invSubBytesTable = []                                               # for decryption

        FILEIN = open(sys.argv[3],"r")
        self.key = BitVector(textstring = FILEIN.read())
        FILEIN.close()
        #self.key = self.key.permute(self.key_permutation_1)


        
    def gen_subbytes_table(self):
        self.subBytesTable = []
        self.invSubBytesTable = []   
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))
        
    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant


    def gen_key_schedule_256(self, key_bv):
        self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, self.subBytesTable)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    self.subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    def genTables(self):
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))
        
    def encrypt( self , plaintext :str , ciphertext :str ) -> None :

        bv = BitVector(filename = plaintext)
        #ciphertext = open(ciphertext, "w")
        encrypted_output = BitVector(size = 0)

        FILEOUT = open(sys.argv[4], "w")

        block = 0

        #generate the key schedule and round keys 

        key_words = self.gen_key_schedule_256(self.key)

        key_schedule = []
       #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            #if word_index % 4 == 0: print("\n")
            #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                        key_words[i*4+3])
        #print("\n\nRound keys in hex (first key for input block):\n")
        #for round_key in round_keys:
            #print(round_key)

        #now we can start reading block by block

        while (bv.more_to_read):
            print("we are in block", block)
            block += 1
            bitvec = bv.read_bits_from_file( 128 )
            if bitvec._getsize() > 0:
                if(bitvec._getsize() < 128):
                    bitvec.pad_from_right(128 - bitvec._getsize())

                #now that we have the round keys we can xor it with the 128 bit block
                #print("\nfirst round key\n")
                #print(round_keys[0])

                #print("\nblock\n")
                #print(bitvec)
                bitvec ^= round_keys[0]
                # print("\nbitvec after xor")
                # print(bitvec.get_bitvector_in_hex())
                # print("\n")

                #generate the state array of 4x4 bytes for the block
                statearray = [[0 for x in range(4)] for x in range(4)]

                for i in range(4):
                    for j in range(4):
                        statearray[j][i] = bitvec[32*i + 8*j:32 * i + 8*(j + 1)]

                # for i in range(4):
                #     sys.stdout.write("\n\n")
                #     for j in range(4):
                #         sys.stdout.write( str(statearray[i][j]) )
                #         sys.stdout.write("\t")
                # sys.stdout.write("\n\n")

                #14 rounds for the 256 bit key
                for x in range(14):
                    print("we are in round", x)

                #start with the sub bytes step
                ##########################################################
                    self.genTables()
                    #print(self.subBytesTable)
                    for i in range(4):
                        for j in range(4):
                            # print("\nstate array value:")
                            # print(statearray[i][j])
                            # print("\n")
                            [LE, RE] = statearray[i][j].divide_into_two()

                            LE = int(LE)
                            RE = int(RE)

                            # print("LE and RE\n")
                            # print(LE, RE)
            
                            statearray[i][j] = hex(self.subBytesTable[LE * 16 + RE])


                    # print("\nstate array after first sub")
                    # print(statearray[0])
                    # print("\n")
                    # print(statearray)
                            
                #now we enter the Shift Rows Step
                ########################################################## 

                    #Circularly shift the second row by 1 byte to the left 
                    for i in range(4):
                        statearray[i] = statearray[i][i:] + statearray[i][:i]

                    # print("\nthis is after shift rows:\n")
                    # print(statearray)

                    for i in range(4):
                        for j in range(4):
                            statearray[i][j] = BitVector(hexstring = statearray[i][j][2:])


                #now we enter the Mix Columns Step
                ########################################################## 
                    state_array_cpy = [row[:] for row in statearray]

                    if(x != 13):
                        for i in range(4):
                            for j in range(4):
                                if(i == 0):
                                    statearray[i][j] = state_array_cpy[2][j] ^ state_array_cpy[3][j] ^ state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="2"), self.AES_modulus, 8) ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="3"), self.AES_modulus, 8)
                                elif(i == 1):
                                    statearray[i][j] = state_array_cpy[0][j] ^ state_array_cpy[3][j] ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="2"), self.AES_modulus, 8) ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="3"), self.AES_modulus, 8)
                                elif(i == 2):
                                    statearray[i][j] = state_array_cpy[0][j] ^ state_array_cpy[1][j] ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="2"), self.AES_modulus, 8) ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="3"), self.AES_modulus, 8)
                                elif(i == 3):
                                    statearray[i][j] = state_array_cpy[1][j] ^ state_array_cpy[2][j] ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="2"), self.AES_modulus, 8) ^ state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="3"), self.AES_modulus, 8)
                    # print("\nState array after mix columns\n")

                    # for i in range(4):
                    #     for j in range(4):
                    #         print(statearray[i][j].get_bitvector_in_hex())
                    #     print("\n")
                                    


                #now we enter the add roundkey Step
                ##########################################################
                    add_roundkey = round_keys[x + 1] 
                    roundkey_array = [[0 for x in range(4)] for x in range(4)]
                    for i in range(4):
                        for j in range(4):
                            roundkey_array[j][i] = add_roundkey[32*i + 8*j:32 * i + 8*(j + 1)]

                    for i in range(4):
                        for j in range(4):
                            statearray[i][j] = statearray[i][j] ^ roundkey_array[i][j]


                    # print("\nState array after round keys\n")

                    # for i in range(4):
                    #     for j in range(4):
                    #         print(statearray[j][i].get_bitvector_in_hex())
                    #     print("\n")
                for i in range(4):
                    for j in range(4):
                        FILEOUT.write((statearray[j][i]).get_bitvector_in_hex())        
                        encrypted_output += statearray[j][i]

                        
        #FILEOUT = open(sys.argv[4], "w")
        FILEOUT.write(encrypted_output.get_bitvector_in_hex())
        FILEOUT.close()

    # decrypt - method performs AES decryption on the
    #ciphertext and writes the
    #recovered plaintext to disk
    # Inputs : ciphertext (str) - filename containing ciphertext
    # decrypted (str) - filename containing recovered plaintext
    # Return : void
        
        
    def decrypt ( self , ciphertext :str , decrypted :str ) -> None :

        FILEIN = open(sys.argv[2], "r")
        bv = BitVector(hexstring = FILEIN.read())
        FILEIN.close()
        #bv = BitVector(filename = ciphertext)
        #bv = bv.get_bitvector_in_hex()
        decrypted_output = BitVector(size = 0)

        block = 0

        #generate the key schedule and round keys 

        key_words = self.gen_key_schedule_256(self.key)

        key_schedule = []
       #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            #if word_index % 4 == 0: print("\n")
            #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                        key_words[i*4+3])
        #print("\n\nRound keys in hex (first key for input block):\n")
        #for round_key in round_keys:
            #print(round_key)
    
        #round_keys1 = round_keys.reverse()

        FILEOUT = open(sys.argv[4], "w")

        #now we can start reading block by block
        for x in range(bv.length() // 128):
            bitvec = bv[128 * x: (x+1)* 128]
            print("we are in block", block)
            block += 1
            #bitvec = bv.read_bits_from_file( 128 )
            if bitvec._getsize() > 0:
                if(bitvec._getsize() < 128):
                    bitvec.pad_from_right(128 - bitvec._getsize())

                print(bitvec.get_bitvector_in_hex())
                bitvec ^= round_keys[-1]
                print("this is the bitvec after first coundkey\n")
                print(bitvec.get_bitvector_in_hex())
        
                #generate the state array of 4x4 bytes for the block
                statearray = [[0 for x in range(4)] for x in range(4)]

                for i in range(4):
                    for j in range(4):
                        statearray[j][i] = bitvec[32*i + 8*j:32 * i + 8*(j + 1)]


                # for i in range(4):
                #     for j in range(4):
                #         statearray[i][j] = statearray[i][j] ^ roundkey_array[i][j]

                # print("first roundkey added for decryption\n")
                # for i in range(4):
                #         for j in range(4):
                #             print(statearray[i][j].get_bitvector_in_hex())
                #             #print(statearray[i][j].get_bitvector_in_hex())
                #         print("\n")

                #14 rounds for the 256 bit key
                for x in range(14):
                    print("we are in round", x)


                    #start with inverse shift rows
                    ################################
                    for i in range(1,4,1):
                        '''
                        (1): [1][3] + [1][0:3] -> [1][3]+ [1][0]+    [1][1]+ [1][2]
                        (2): [2][2:4] + [2][0:2] -> [2][2] + [2][3]+ [2][0] + [2][1]
                        (3): [3][1:4] + [3][:1] -> [3][1] + [3][2] + [3][3] + [3][0]
                        '''
                        statearray[i] = statearray[i][4 - i:] + statearray[i][:4 - i]

                    # print("inverse shift rows for decryption\n")
                    # for i in range(4):
                    #         for j in range(4):
                    #             print(statearray[i][j].get_bitvector_in_hex())
                    #         print("\n")


                    #inverse substitute bytes
                    ###########################
                    self.genTables()
                    #print(self.subBytesTable)
                    for i in range(4):
                        for j in range(4):
                            # print("\nstate array value:")
                            # print(statearray[i][j])
                            # print("\n")
                            [LE, RE] = statearray[i][j].divide_into_two()

                            LE = int(LE)
                            RE = int(RE)

                            # print("LE and RE\n")
                            # print(LE, RE)
            
                            statearray[i][j] = hex(self.invSubBytesTable[LE * 16 + RE])


                    
                    #convert statearray into bitvector values
                    for i in range(4):
                        for j in range(4):
                            statearray[i][j] = BitVector(hexstring = statearray[i][j][2:])


                    # print("sub bytes for decryption\n")
                    # for i in range(4):
                    #         for j in range(4):
                    #             print(statearray[i][j].get_bitvector_in_hex())
                    #         print("\n")

                    #add roundkey
                    ###########################
                    add_roundkey = round_keys[13 - x] 
                    roundkey_array = [[0 for x in range(4)] for x in range(4)]
                    for i in range(4):
                        for j in range(4):
                            roundkey_array[j][i] = add_roundkey[32*i + 8*j:32 * i + 8*(j + 1)]


                    for i in range(4):
                        for j in range(4):
                            statearray[i][j] = statearray[i][j] ^ roundkey_array[i][j]



                    #inverse mix columns
                    ##########################
                    state_array_cpy = [row[:] for row in statearray]

                    if(x != 13):
                        for i in range(4):
                            for j in range(4):
                                if(i == 0):
                                    statearray[i][j] = state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="E"), self.AES_modulus, 8) ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="B"), self.AES_modulus, 8) ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="D"), self.AES_modulus, 8) ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="9"), self.AES_modulus, 8)
                                elif(i == 1):
                                    statearray[i][j] = state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="9"), self.AES_modulus, 8) ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="E"), self.AES_modulus, 8) ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="B"), self.AES_modulus, 8) ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="D"), self.AES_modulus, 8)
                                elif(i == 2):
                                    statearray[i][j] = state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="D"), self.AES_modulus, 8) ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="9"), self.AES_modulus, 8) ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="E"), self.AES_modulus, 8) ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="B"), self.AES_modulus, 8)
                                elif(i == 3):
                                    statearray[i][j] = state_array_cpy[0][j].gf_multiply_modular(BitVector(hexstring="B"), self.AES_modulus, 8) ^ state_array_cpy[1][j].gf_multiply_modular(BitVector(hexstring="D"), self.AES_modulus, 8) ^ state_array_cpy[2][j].gf_multiply_modular(BitVector(hexstring="9"), self.AES_modulus, 8) ^ state_array_cpy[3][j].gf_multiply_modular(BitVector(hexstring="E"), self.AES_modulus, 8)

                for i in range(4):
                    for j in range(4):     
                        FILEOUT.write((statearray[j][i]).get_bitvector_in_ascii())   
                        decrypted_output += statearray[j][i]


                        
        #FILEOUT = open(sys.argv[4], "w")
        #FILEOUT.write(decrypted_output.get_bitvector_in_ascii())
        FILEOUT.close()
        
                

    
if __name__ == "__main__":
    cipher = AES ( keyfile = sys . argv [3])

    if sys.argv [1] == "-e":
        cipher.encrypt ( plaintext = sys . argv [2], ciphertext = sys .
                                    argv [4])
    elif sys.argv [1] == "-d":
        cipher.decrypt ( ciphertext = sys . argv [2], decrypted = sys .
                                        argv [4])
    else :
        sys . exit (" Incorrect Command - Line Syntax ")