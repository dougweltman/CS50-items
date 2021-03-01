from sys import argv, exit
import csv

# returns the max number of times key repeats in string called genome.


def count_keys(key, genome):
    # store results in an array whose elements correspond to each base pair of genome.
    key_length = len(key)
    counter_results = []

    #  for loop uses counter_results[]
    for i in range(len(genome)):
        counter_results.append(0)
        # if this is a match, keep going and see how many more there are!
        if (genome[i:i+key_length] == key):
            counter_results[i] += 1
            new_point = i+key_length
            # inner loop sees if there are any further matches and adds 1 each time it hits a match.
            for j in range(new_point, len(genome), key_length):
                if (genome[j:j+key_length] == key):
                    counter_results[i] += 1
                else:
                    break
    return max(counter_results)


# Main function
if len(argv) != 3:
    print("Usage: python dna.py data.csv sequence.txt")
    exit(1)

# DB values. This is an array we'll search through.
db_values = []

# Extracts DB into memeory and builds list of STRs we're looking for.
with open(argv[1], newline="") as db_file:
    db_reader = csv.reader(db_file)
    for row in db_reader:
        db_values.append(row)

# Reference list. This tells us the list of STRs we'll need to look for.
STRs_listed = (db_values[0][1:])
names_list = (db_values[0:4][0])

# Opens the text file and saves DNA sequence to person_seq, a string.
with open(argv[2], newline="") as person_file:
    person_seq = person_file.read()

# Build the list of max STRs given person_seq and str_list. Should return a list of ints.

# build a fingerprint dictionary for the person. This should use the STR as the reference, and the max count of the respective STRs as entries.
fingerprint = []
for i in range(len(STRs_listed)):
    # needs to be array of *strings* to compare to DB items, which are also strings.
    fingerprint.append(str(count_keys(STRs_listed[i], person_seq)))

# we now have a list object called "fingerprint" that we can use to compare against DB entries.
# iterate through DB. Compare if fingerprint matches the entry.
for i in range(1, len(db_values)):  # skip first row of DB.
    if (db_values[i][1:] == fingerprint):
        print(db_values[i][0])
        break
    else:
        if (i == len(db_values)-1):
            print("No match")
