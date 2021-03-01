import cs50

def countLetters(txt):
    n = 0
    for char in txt:
        if char.isalnum():
            n += 1
    return n


def countWords(txt):
    n = 0
    parsed = txt.split(" ")
    return len(parsed)


def countSentences(txt):
    n = 0
    for char in txt:
        if char in (".", "!", "?"):
            n += 1
    return n


def Coleman_Liau(l, s):
    n = (0.0588 * l - 0.296 * s - 15.8)
    return n


text = cs50.get_string("Text: ")
letters = countLetters(text)
words = countWords(text)
sentences = countSentences(text)
l = letters * 100/words
s = sentences * 100/words

grade = Coleman_Liau(l, s)

if (grade < 1):
    print("Before Grade 1")
elif (grade >= 16):
    print("Grade 16+")
else:
    print("Grade {}".format(round(grade)))
