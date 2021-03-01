// Implements a dictionary's functionality

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dictionary.h"

// Represents number of buckets in a hash table
#define N 26

// Represents a node in a hash table
typedef struct node
{
    char word[LENGTH + 1];
    struct node *next;
}
node;

// Declares an array of nodes called Hashtable.
node *hashtable[N];

//Declares the head of the hashtable.
node *HEAD;

// Hashes word to a number between 0 and 25, inclusive, based on its first letter
// Does this by returning an int on a function that takes a char pointer as input.
unsigned int hash(const char *word)
{
    return tolower(word[0]) - 'a';
}

// Initialize value of the starting location of the head pointer so that we know if the full linked list has loaded.
// This will later be used for the first location of head.
//node *head_starting_location;

//prototype function for creating nodes.
int create(char* word);

// Loads dictionary into memory, returning true if successful else false
bool load(const char *dictionary)
{
    // Initialize hash table
    // This should give us an array of 26 notes, each element called hashtable[i].
    for (int i = 0; i < N; i++)
    {
        hashtable[i] = malloc(sizeof(node));
    }
    HEAD = malloc(sizeof(node));
    printf("HEAD Value: %s, HEAD Location: %p, HEAD Pointer: %p\n", HEAD -> word, &HEAD, HEAD -> next);

    // Open dictionary
    FILE *file = fopen(dictionary, "r");
    if (file == NULL)
    {
        unload();
        return false;
    }

    // Buffer for a word
    char word[LENGTH + 1];

// Insert words into hash table

    //Store in memory the initial location of head.
    //head_starting_location = head;

    //Extract words from file.
    while(fscanf(file, "%s", word) != EOF)
    {
        //hash the word.
        int i = hash(word);
        printf("loading word: %s\nhashed value: %i\n",word,i);

        //create a node from the word.
        create(word);
        printf("%s loaded.\n\n", word);

        //if head is not null, copy it to current.
       /*if (head->word != NULL)
        {
            current->word = head->word;
            current->next = head->next;
        }*/

        //now, (re-)create head.


        // TODO


        //int i = fscanf(file, "%s", word);
        //printf("fscanf: %i\n", i);


    }

    // Close dictionary
    fclose(file);

    // Indicate success
    return true;
}

// Returns number of words in dictionary if loaded else 0 if not yet loaded
unsigned int size(void)
{
    // TODO
    return 0;
}

// Returns true if word is in dictionary else false
bool check(const char *word)
{
    // TODO
    return false;
}

// Unloads dictionary from memory, returning true if successful else false
bool unload(void)
{
    // TODO
    return false;
}

int create(char* word)
{
    //Create space in memory for a new node for word.
    node * new_word = malloc(sizeof(node));
    if (new_word == NULL) return 1;
    strcpy(new_word -> word, word);
    printf("Successfully copied. \n");

    //Finds the hash value for the new word.
    int i = hash(word);
    printf("Successfully hashed.\n");

    printf("Hashtable Value: %s, Hashtable Address: %p, Hashtable Location: %p\n", hashtable[i]->word, hashtable[i]->next, &hashtable[i]);


    /*
    Check if we can use hashtable[i] as the head.
    If hashtable has other values (i.e., this is not the first word for a given letter),
    then navigate down the chain.
    */
    if(hashtable[i] -> next != NULL)
    {
        printf("Existing Hash Table: copied: %s at location %p\n",new_word -> word, new_word -> next);
        new_word -> next = HEAD;

    }
    else
    {
        //Indicate to user this tree fired.
        printf("New Hash Table: copied: %s at location %p\n",new_word -> word, new_word -> next);
        //
        hashtable[i] -> next = HEAD;
        new_word -> next = hashtable[i];
        printf("New word next: %p\n", new_word -> next);
    }

    /*
    Set head to be equal to the new word. That lets us insert more words
    beyond hashtable[i] using the logic above.
    */
    HEAD = new_word;
    printf("HEALTH CHECK>>>\n");
    printf("HEAD word: %s, HEAD next: %p, HEAD address: %p\n", HEAD->word, HEAD->next, &HEAD);
    printf("New word: %s, New next: %p, New address: %p\n", new_word->word, new_word->next, &new_word);
    printf("Hashtable word: %s, Hashtable next: %p, Hashtable address: %p\n", hashtable[i]->word, hashtable[i]->next, &hashtable[i]);

    return 0;
}
