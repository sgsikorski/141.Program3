/* Prog3Vigenere.cpp
 *     Encode/Decode using Vigenere cipher.
 */

#include <iostream>   // For Input and Output
#include <fstream>    // For file input and output
#include <cctype>     // Allows using the tolower() function
#include <cstring>    // Allows for C-string manipulation
using namespace std;

// Global constants
// Max string size, and the Vigenere table that is used to encode and decode the messages
int const MAX_STRING_SIZE = 81;
char const VIGENERE_TABLE[26][26] = {
{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'},
{'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a'},
{'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b'},
{'d', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c'},
{'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd'},
{'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e'},
{'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f'},
{'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g'},
{'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'},
{'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'},
{'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'},
{'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'},
{'m', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'},
{'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'},
{'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'},
{'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'},
{'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
{'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q'},
{'s', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r'},
{'t', 'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's'},
{'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't'},
{'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u'},
{'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'},
{'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'},
{'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x'},
{'z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y'}
};

// findWord function with a C-String parameter, lookupWord
// Takes lookupWord and checks dictionary.txt using binary search to see if loopupWord is in it
int findWord(char lookupWord[]){
    // Declaring the array of dictionary words, and the word that will be read in
    char dictionaryArray[DICTIONARY_SIZE][MAX_STRING_SIZE];
    char nextWord[MAX_STRING_SIZE];
    // Opens the dictionary.txt file and if it doesn't open, it shoots an error
    ifstream inStream;
    inStream.open("dictionary.txt");
    if(!inStream.is_open()){
        cout << "Couldn't find dictionary.txt. Exiting...." << endl;
        exit(-1);
    }
    
    // File takes in the next word of the file
    int dictionarySize = 0;
    while(inStream >> nextWord){
        // If the length of word is >= 3, the word is put into the dictionary array
        if(strlen(nextWord) >= 3){
            for (int j = 0; j < strlen(nextWord); j++){
               dictionaryArray[i][j] = nextWord[j];
            }
            dictionarySize++;
        }
    }

    // Converts all dictionary words and the lookupWord to lowercase
    for (int i = 0; i < strlen(lookupWord); i++){
        lookupWord[i] = tolower(lookupWord[i]);
    }
    for (int i = 0; i < dictionarySize; i++){
        for (int j = 0; j < strlen(dictionaryArray[i]); j++){
            dictionaryArray[i][j] = tolower(dictionaryArray[i][j]);
        }
    }
    
    // Binary search to look for lookupWord
    int lower = 0;
    int upper = dictionarySize;
    while(lower <= upper){
        int mid = lower + (upper - lower) / 2;
        if(strcmp(lookupWord, dictionaryArray[mid]) == 0){
            return 1;
        }
        if(strcmp(lookupWord, dictionaryArray[mid]) > 0){
            lower = mid + 1;
        }
        if(strcmp(lookupWord, dictionaryArray[mid]) < 0){
            upper = mid - 1;
        }
    }

    return 0;
} 

// encodeText function with parameters C-Strings userInput, encodeUserKeyword, cipherText
void encodeText(char userInput[], char encodeUserKeyword[], char cipherText[]){
    // Declares a temp to copy to
    // Repeats the keyword for the length of userInput
    char temp[MAX_STRING_SIZE];
    for(int i = 0; i < strlen(userInput); i++){
        temp[i] = encodeUserKeyword[i % strlen(encodeUserKeyword)];
    }
    for (int i = 0; i < strlen(userInput); i++){
       encodeUserKeyword[i] = temp[i];
    }
    encodeUserKeyword[strlen(userInput)] = '\0';
    
    // Convers userInput and encodeUserKeyword to lowercase
    for (int i = 0; i < strlen(encodeUserKeyword); i++){
       userInput[i] = tolower(userInput[i]);
       encodeUserKeyword[i] = tolower(encodeUserKeyword[i]);
    }

    // Encoding algorithm
    for (int i = 0; i < strlen(userInput); i++){
        int rowInt;
        int colInt;
        for (int j = 0; j < 26; j++){
            // Finds the corresponding letter for userInput and indicates which rowInt it is
            if(userInput[i] == VIGENERE_TABLE[0][j]){
                rowInt = j;
            }
            // Finds the corresponding letter for encodeUserKeyword and indicates which colInt it is 
            if(encodeUserKeyword[i] == VIGENERE_TABLE[j][0]){
                colInt = j;
            }
        } 
        // Checks if current character is a letter, if not, keeps that special characters.
        // If so, then it takes which rowInt and colInt it is and finds the encoding character
        if(isalpha(userInput[i])){
            cipherText[i] = VIGENERE_TABLE[rowInt][colInt];
        } 
        else if(userInput[i] == ' '){
           cipherText[i] = userInput[i];
        } else{
            cipherText[i] = userInput[i];
        }
    }
    cipherText[strlen(userInput)] = '\0';

}

// decodeText function with parameters C-Strings cipherText, userKeyword, decodedText
void decodeText(char cipherText[], char userKeyword[], char decodedText[]){
    // Declares temp to copy to and copy of the singular keyword
    char temp[MAX_STRING_SIZE];
    char originalKeyword[MAX_STRING_SIZE];
    strcpy(originalKeyword, userKeyword);
    // Repeats the keyword for the length of userInput
    for (int i = 0; i < strlen(cipherText); i++){
       temp[i] = userKeyword[i % strlen(userKeyword)];
    }
    strcpy(userKeyword, temp);
    
    // Convers cipherText and userKeyword to lowercase
    for (int i = 0; i < strlen(cipherText); i++){
       cipherText[i] = tolower(cipherText[i]);
       userKeyword[i] = tolower(userKeyword[i]);
    }
    
    // Checks if current character of cipherText is a letter, if not, then copies the special character and continues
    for (int i = 0; i < strlen(cipherText); i++){
        if(!isalpha(cipherText[i])){
            decodedText[i] = cipherText[i];
            continue;
        }
        // Finds the colInt from the corresponding userKeyword letter
        int colInt;
        for (int j = 0; j < 26; j++){
            if(userKeyword[i] == VIGENERE_TABLE[j][0]){
                colInt = j;
            }
        }
        // Finds the letter from column of colInt and gets the row the cipher letter is in and sets it to rowInt
        for (int j = 0; j < 26; j++){
            if(cipherText[i] == VIGENERE_TABLE[colInt][j]){
                decodedText[i] = VIGENERE_TABLE[0][j];
            }
        }
        
    }
    // Counts the amount of words that is in decodedText
    int numberOfWords = 0;
    for (int i = 0; i < strlen(decodedText); i++){
      if(decodedText[i] == ' '){
         numberOfWords++;
      }
    }
    if(numbersOfWords > 1){
        cout << numberOfWords << " words found using keyword: " << originalKeyword << " giving:" << endl << "   "<< decodedText << endl;
    }
}

// autoDecode function with parameters C-String autoDecodeText
void autoDecode(char autoDecodeText[]){
    // Initialize numberOfValidWords, and opens the file
    int numberOfValidWords = 0;
    ifstream inStream;
    inStream.open("TheSecretAgentByJosephConrad.txt");
    // Exits if the file can't be found
    if(!inStream.is_open()){
        cout << "Couldn't find TheSecretAgentByJosephConrad.txt. Exiting..." << endl;
        exit(-1);
    }
    // Initialize the array of keyword from TheSecretAgent book, and the keyword
    char nextKeyword[MAX_STRING_SIZE];
    char keywordArray[93297][MAX_STRING_SIZE];
    int i = 0;
    // Takes in the next word for the file
    while(inStream >> nextKeyword){
       if(strlen(nextKeyword) < 2){
          continue;
       }
       int k = 0;
       // Checks if the keyword has only letters, if not skips over the letter and uses the keyword with only letters
       for (int j = 0; j < strlen(nextKeyword); j++){
          if(isalpha(nextKeyword[j])){
             nextKeyword[k] = nextKeyword[j];
             k++;
          } else{
             continue;
          }
       }
       // Converts the keyword to lowercase
       for (int j = 0; j < strlen(nextKeyword); j++){
          nextKeyword[j] = tolower(nextKeyword[j]);
       }
       
       strcpy(keywordArray[i], nextKeyword);
       
       // Runs decodeText using the autoDecodeText from the user, every keyword in the array and decodes it to possibleDecode
       char possibleDecode[MAX_STRING_SIZE] = "";
       decodeText(autoDecodeText, keywordArray[i], possibleDecode);
       
       char lookupWords[20][MAX_STRING_SIZE];
       int j = 0;
       int ctr = 0;
       
       // Seperate the spaces of the autoDecodeText and puts the words in an array
       for (int k = 0; k < strlen(possibleDecode); k++){
          if(!isalpha(possibleDecode[k])){
             lookupWords[ctr][j] = '\0';
             ctr++;
             j = 0;
          } else{
             lookupWords[ctr][j] = possibleDecode[k];
             j++;
          }
       }
       
       // Using the array of words from the possibleDecode, checks if word is valid using the findWord function.
       for (int k = 0; k < 20; k++){
          if(findWord(lookupWords[k])){
             numberOfValidWords++;
          }
       }
       if(numberOfValidWords > 0){
          cout << possibleDecode << endl << numberOfValidWords << endl;
       }
       i++;
    } // end of while loop
}

//---------------------------------------------------------------------------
int main()
{
    // Declare variables
    int menuOption;                   // Userinput for menu option
    char returnCharacter;             // Separately store the return character so cin.getline does not consider it the next user input
    
    cout << DICTIONARY_SIZE << " words of size >= 3 were read in from dictionary. " << endl << endl;
    // Display menu and handle menu options
    cout << "Choose from the following options: \n"
         << "    1. Lookup dictionary word \n"
         << "    2. Encode some text  \n"
         << "    3. Decode some text  \n"
         << "    4. Auto-decode the ciphertext given with the assignment  \n"
         << "    5. Exit program  \n"
         << "Your choice: ";
        cin >> menuOption;
        returnCharacter = cin.get();  // Read and discard the return character at the end of the above input line.
                                      // This is necessary because otherwise a subsequent cin.getline() reads it as
                                      // an empty line of input.
    switch( menuOption) {
        case 1: // Do dictionary lookup of a word and indicate whether or not it was found.
            // Takes in a user input of lookupWord 
            char lookupWord[MAX_STRING_SIZE];
            cout << "Enter a word to be looked up in dictionary: ";
            cin >> lookupWord;
            
            // Tries findword for lookupWord. If false, not in the dictionary, if true, in the dictionary
            if(!findWord(lookupWord)){
                cout << lookupWord << " is NOT in the dictionary." << endl;
            } else{
                cout << lookupWord << " IS in the dictionary." << endl;
            }
            break;
            
        case 2: // Encode some text
            // Initialize user input and the encoded text
            char userInput[MAX_STRING_SIZE];
            char encodeUserKeyword[MAX_STRING_SIZE];
            char encodeCipherText[MAX_STRING_SIZE];

            // Takes in a whole line of input and then clears the cin buffer
            cout << "Enter the text to be encoded: ";
            cin.getline(userInput, MAX_STRING_SIZE);
            cin.clear();
            cout << "Enter a keyword for Vigenere encryption: ";
            cin.getline(encodeUserKeyword, MAX_STRING_SIZE);
            cin.clear();
            
            // Encodes text and then prints the keyword, userInput and encoded text
            encodeText(userInput, encodeUserKeyword, encodeCipherText);
            cout << "Keyword, plainText and ciphertext are:  \n";
            cout << encodeUserKeyword << endl << userInput << endl << encodeCipherText << endl;
    
            break;
            
        case 3: // Decode using user-entered values
            // Initialize the user inputted encoded text and keyword and the potential decoded text
            char decodeCipherText[MAX_STRING_SIZE];
            char decodeUserKeyword[MAX_STRING_SIZE];
            char decodedText[MAX_STRING_SIZE];

            // Takes in the encoded text and keyword
            cout << "Enter the cipherText to be decoded: ";
            cin.getline(decodeCipherText, MAX_STRING_SIZE);
            cout << "Enter a Vigenere keyword to be tried: ";
            cin.getline(decodeUserKeyword, MAX_STRING_SIZE);
            
            decodeText(decodeCipherText, decodeUserKeyword, decodedText);
            break;
            
        case 4: // Decode ciphertext given with the assignment
            // Initializes the text and gets the text
            char autoDecodeText[MAX_STRING_SIZE];
            cout << "Enter the cipherText to be decoded: ";
            cin.getline(autoDecodeText, MAX_STRING_SIZE);

            // Does autoDecode using autoDecodeText
            autoDecode(autoDecodeText);
            break;
            
        case 5: // exit program
            cout << "Exiting program" << endl;
            exit( 0);
            break;
            
        default:
            // Sanity check
            cout << "Invalid menu option.  Exiting program." << endl;
            break;
    }// end switch( menuOption)
    
    return 0;
}//end main()