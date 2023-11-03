#!/usr/bin/env python3

# Luke Robinson and Courtney Stewart
# COMP 5350 Project 2

#sources:
# https://stackoverflow.com/questions/2269827/how-to-convert-an-int-to-a-hex-string
# https://stackoverflow.com/questions/48613002/sha-256-hashing-in-python
# https://stackoverflow.com/questions/24953303/how-to-reverse-an-int-in-python
# https://stackoverflow.com/questions/931092/how-do-i-reverse-a-string-in-python
# https://www.garykessler.net/library/file_sigs.html
# https://stackoverflow.com/questions/2269827/how-to-convert-an-int-to-a-hex-string
# https://stackoverflow.com/questions/22901285/taking-a-hex-file-and-extracting-data
# https://stackoverflow.com/questions/931092/how-do-i-reverse-a-string-in-python
# https://stackoverflow.com/questions/3398410/python-get-number-without-decimal-places


import sys
import os
import math
import hashlib

try:
    imageFile = sys.argv[1]
    with open(imageFile, 'rb') as disk:
        diskHex = disk.read().hex()
    disk.close()
except FileNotFoundError:
    sys.exit("File Not Found")

def recoverPDF():
    pdfCount = 0
    signatureIndex = 0
    pdfSig = "25504446"
    pdfTrail = "0a2525454f460a", "0a2525454f46", "0d0a2525454f460d0a", "0d25254f4f460d"

    location = 0
    indexList = []
    while location < len(diskHex):
        pdfLocation = diskHex.find(pdfSig, location)
        if pdfLocation % 512 == 0:
            indexList.append(pdfLocation)
        location = pdfLocation + 7
        if location == 6: break

    for i in range (len(indexList)):
        startIndex = indexList[i]
        if indexList[i] == indexList[-1]:
            searchLocation = diskHex[indexList[-1]:]
        else: 
            searchLocation = diskHex[indexList[i]:indexList[i+1]]

        start_offset = int(startIndex / 2)
        end_offset = int(findLastEof(searchLocation, pdfTrail) / 2) + start_offset

        hex_start = hex(start_offset)
        hex_end = hex(end_offset)
        pdfCount += 1
        fileName = fileName = 'PDFfile' + str(pdfCount) + '.pdf'
        print("pdf file found: " + fileName + "\n" + f"start offset: {hex_start}" + "\t" + f"end offset: {hex_end}")
                
        fileRecovery = 'dd if=' + str(sys.argv[1]) + ' of=' + fileName + ' bs=512 skip=' + str(int(start_offset / 512)) + ' count=' + str(math.ceil((end_offset-start_offset) / 512)) + ' 2>error_log.txt &'
        os.system(fileRecovery)

        hashCmd = "sha256sum " + fileName
        print("sha256 hash: ")
        os.system(hashCmd)
        print('\n')
    return 0
def recoverMPG():
    mpgCount = 0
    signatureIndex = 0
    mpgSig = "000001b3"
    mpgTrail = "000001b7", "000001b9"
    while True:
        signatureIndex = diskHex.find(mpgSig, signatureIndex)
        if signatureIndex != -1:
            if signatureIndex % 512 == 0:

                mpgCount += 1

                start_offset = int(signatureIndex / 2)
                trailerIndex = diskHex.find(mpgTrail[0], signatureIndex)
                if trailerIndex == -1: trailerIndex = diskHex.find(mpgTrail[1], signatureIndex)
                end_offset = int(((trailerIndex + 7)/ 2))
                hex_start = hex(start_offset)
                hex_end = hex(end_offset)
                fileName = 'MPGfile' + str(mpgCount) + '.mpg'
                print("mpg file found: " + fileName + "\n" + f"start offset: {hex_start}" + "\t" + f"end offset: {hex_end}")
                
                fileRecovery = 'dd if=' + str(sys.argv[1]) + ' of=' + fileName + ' bs=512 skip=' + str(int(start_offset / 512)) + ' count=' + str(math.ceil((end_offset-start_offset) / 512)) + ' 2>error_log.txt &'
                os.system(fileRecovery)

                hashCmd = "sha256sum " + fileName
                print("sha256 hash: ")
                os.system(hashCmd)
                print('\n')
                signatureIndex = end_offset * 2
            else: signatureIndex = signatureIndex + 8
        else: break
    return 0
def recoverBMP():
    bmpCount = 0
    signatureIndex = 0
    bmpSig = "424d"
    while True:
        signatureIndex = diskHex.find(bmpSig, signatureIndex)
        if signatureIndex != -1:
            checkThese = diskHex[(signatureIndex + 12):(signatureIndex + 20)]
            if signatureIndex % 512 == 0 and checkThese == '00000000':

                bmpCount += 1

                beFileSize = getBEfromString(diskHex[signatureIndex:])
                fileSize = int(beFileSize, 16)

                start_offset = int(signatureIndex / 2)
                end_offset = int(start_offset + fileSize)
                hex_start = hex(start_offset)
                hex_end = hex(end_offset)
                fileName = 'BMPfile' + str(bmpCount) + '.bmp'
                print("bmp file found: " + fileName + "\n" + f"start offset: {hex_start}" + "\t" + f"end offset: {hex_end}")
                
                fileRecovery = 'dd if=' + str(sys.argv[1]) + ' of=' + fileName + ' bs=512 skip=' + str(int(start_offset / 512)) + ' count=' + str(math.ceil(fileSize / 512)) + ' 2>error_log.txt &'
                os.system(fileRecovery)

                hashCmd = "sha256sum " + fileName
                print("sha256 hash: ")
                os.system(hashCmd)
                print('\n')
                signatureIndex = end_offset * 2
            else: signatureIndex = signatureIndex + 8
        else: break
    return 0
def recoverGIF():
    gifCount = 0
    signatureIndex = 0
    gifSig = "474946383961", "474946383961" 
    gifTrail = "003b0000"
    while True:
        signatureIndex = diskHex.find(gifSig[0], signatureIndex)
        if signatureIndex != -1:
            if signatureIndex % 512 == 0:

                gifCount += 1

                start_offset = int(signatureIndex / 2)
                trailerIndex = diskHex.find(gifTrail, signatureIndex)
                end_offset = int(((trailerIndex + 7)/ 2))
                hex_start = hex(start_offset)
                hex_end = hex(end_offset)
                fileName = 'GIFfile' + str(gifCount) + '.gif'
                print("gif file found: " + fileName + "\n" + f"start offset: {hex_start}" + "\t" + f"end offset: {hex_end}")
                
                fileRecovery = 'dd if=' + str(sys.argv[1]) + ' of=' + fileName + ' bs=512 skip=' + str(int(start_offset / 512)) + ' count=' + str(math.ceil((end_offset-start_offset) / 512)) + ' 2>error_log.txt &'
                os.system(fileRecovery)

                hashCmd = "sha256sum " + fileName
                print("sha256 hash: ")
                os.system(hashCmd)
                print('\n')
                signatureIndex = end_offset * 2
            else: signatureIndex = signatureIndex + 8
        else: break
    while True:
        signatureIndex = diskHex.find(gifSig[1], signatureIndex)
        if signatureIndex != -1:
            if signatureIndex % 512 == 0:

                gifCount += 1

                start_offset = int(signatureIndex / 2)
                trailerIndex = diskHex.find(gifTrail, signatureIndex)
                end_offset = int(((trailerIndex + 7)/ 2))
                hex_start = hex(start_offset)
                hex_end = hex(end_offset)
                fileName = 'GIFfile' + str(gifCount) + '.gif'
                print("gif file found: " + fileName + "\n" + f"start offset: {hex_start}" + "\t" + f"end offset: {hex_end}")
                
                fileRecovery = 'dd if=' + str(sys.argv[1]) + ' of=' + fileName + ' bs=512 skip=' + str(int(start_offset / 512)) + ' count=' + str(math.ceil((end_offset-start_offset) / 512)) + ' 2>error_log.txt &'
                os.system(fileRecovery)

                hashCmd = "sha256sum " + fileName
                print("sha256 hash: ")
                os.system(hashCmd)
                print('\n')
                signatureIndex = end_offset * 2
            else: signatureIndex = signatureIndex + 8
        else: break
    return 0


#Courtney is doing JPG, DOCX, AVI, and PNG

#sources
#https://www.w3schools.com/python/ref_func_open.asp
#https://docs.python.org/3/library/hashlib.html



#variables
fileName = sys.argv[1]

#recovers files with JPG extension
def JPGrecover():
    print('\nJPG files:\n')
    with open(fileName, 'rb') as f:
        s = f.read()
        index = 0;
        count = 0;
        try:
            while True:
                #for JPG files the starting signature is 0xFF D8
                index = s.index(b'\xFF\xD8', index)

                #check if we're at the start of a sector 
                #if we aren't increment, if we are continue
                if (index % 0x1000 != 0):
                    index += 2
                    continue

                #JPG files have footer of 0xFF D9, trailing with 00's to ensure end
                endIndex = s.index(b'\xFF\xD9\x00\x00\x00\x00', index) + 1

                #write contents to file
                writtenFile = open(str(count) + ".jpg", "wb")
                writtenFile.write(s[index:endIndex + 1])
                writtenFile.close()
                print('File contents written to ' + str(count) + '.jpg')

                #print offset info
                print('Start Offset: ' + hex(index))
                print('End Offset: ' + hex(endIndex))

                #get hash info
                hash = hashlib.sha256(s[index:endIndex + 1]).hexdigest()
                print('SHA-256: ' + hash)

                #increment index to continue checking for JPG files
                index = endIndex
                count += 1
                print()
        except ValueError:
            print("End of file")
        print(str(count) + ' JPG files found')
    return count

#recover files with DOCX extension
def DOCXrecover():
    print('\nDOCX Files:\n')
    with open(fileName, 'rb') as f:
        s = f.read()
        index = 0
        count = 0

        try:
            while True:
                #for DOCX files the header is 0x50 4B 03 04 14 00 06 00
                index = s.index(b'\x50\x4B\x03\x04\x14\x00\x06\x00', index)
                if(index % 0x1000 != 0):
                    index += 8
                    continue

                #DOCX has footer of 0x50 4B 05 06 followed by 18 bytes 
                endIndex = s.index(b'\x50\x4B\x05\x06', index) + 21

                writtenFile = open(str(count) + ".docx", "wb")
                writtenFile.write(s[index:endIndex + 1])
                writtenFile.close()
                print('File contents written to ' + str(count) + '.docx')

                #print offset info
                print('Start Offset: ' + hex(index))
                print('End Offset: ' + hex(endIndex))

                #get hash info
                hash = hashlib.sha256(s[index:endIndex + 1]).hexdigest()
                print('SHA-256: ' + hash)

                #increment to keep checking for other DOCX files
                index = endIndex
                count += 1
                print()
        except ValueError:
            print("End of file")
        print(str(count) + ' DOCX file found')
    return count

#recover files with AVI extension
def AVIrecover():
    print('\nAVI Files:\n')
    with open(fileName, 'rb') as f:
        s = f.read()
        index = 0
        count = 0

        try:
            while True:
                #for AVI files the RIFF header is 0x52 49 46 46
                #then the actual AVI header is 0x41 56 49 20 4C 49 53 54
                index = s.index(b'\x52\x49\x46\x46', index)

                if(index + 8 != s.index(b'\x41\x56\x49\x20\x4C\x49\x53\x54', index)):
                    index += 4
                    continue

                if(index % 0x1000 != 0):
                    index += 4
                    continue


                #find the file size
                #which is in spot 4-8 (in little endian)
                sizeAVI = int.from_bytes(s[index + 4:index + 8], 'little')
                endIndex = index + sizeAVI

                writtenFile = open(str(count) + ".avi", "wb")
                writtenFile.write(s[index:endIndex + 1])
                writtenFile.close()
                print('File contents written to ' + str(count) + '.avi')

                #print offset info
                print('Start Offset: ' + hex(index))
                print('End Offset: ' + hex(endIndex))

                #get hash info
                hash = hashlib.sha256(s[index:endIndex + 1]).hexdigest()
                print('SHA-256: ' + hash)

                #increment to keep checking for other AVI files
                index = endIndex
                count += 1
                print()
        except ValueError:
            print("End of file")
        print(str(count) + ' AVI files found')
    return count

#recover files with PNG extension
def PNGrecover():
    print('\nPNG Files:\n')
    with open(fileName, 'rb') as f:
        s = f.read()
        index = 0
        count = 0

        try:
            while True:
                #for PNG files the header is 0x89 50 4E 47 0D 0A 1A 0A
                index = s.index(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', index)
                if(index % 0x1000 != 0):
                    index += 8
                    continue

                #PNG has footer of 0x49 45 4E 44 AE 42 60 82
                endIndex = s.index(b'\x49\x45\x4E\x44\xAE\x42\x60\x82', index) + 7

                writtenFile = open(str(count) + ".png", "wb")
                writtenFile.write(s[index:endIndex + 1])
                writtenFile.close()
                print('File contents written to ' + str(count) + '.png')

                #print offset info
                print('Start Offset: ' + hex(index))
                print('End Offset: ' + hex(endIndex))

                #get hash info
                hash = hashlib.sha256(s[index:endIndex + 1]).hexdigest()
                print('SHA-256: ' + hash)

                #increment to keep checking for other PNG files
                index = endIndex
                count += 1
                print()
        except ValueError:
            print("End of file")
        print(str(count) + ' PNG file found')
    return count

#to find total number of recovered files:

# numRecovered = 0
# numRecovered += recoverMPG()
# numRecovered += recoverPDF()
# numRecovered += recoverBMP()
# numRecovered += recoverGIF()
# numRecovered += JPGrecover()
# numRecovered += DOCXrecover()
# numRecovered += AVIrecover()
# numRecovered += PNGrecover()
# print('\nNumber of recovered files: ' + str(numRecovered))

def getBEfromString(input_string):
    beString = input_string[10:12] + input_string[8:10] + input_string[6:8]+ input_string[4:6]
    return beString

def findLastEof(input_string: str, eofList: list) -> int:
    currentLast = 0
    for x in eofList:
        eofLoc = input_string.find(x, currentLast)
        if eofLoc > currentLast: currentLast = eofLoc
    return currentLast + len(x) - 1

if __name__ == "__main__":
    recoverMPG()
    recoverBMP()
    recoverGIF()
    recoverPDF()

    JPGrecover()
    DOCXrecover()
    AVIrecover()
    PNGrecover()

    print("Recovered files can be found in: ")
    os.system('pwd')
