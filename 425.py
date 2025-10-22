print("Test")

try:
    with open('../p3-425/425-r.txt', 'r') as file:
        for line in file:
            # if 2nd to last character is not -, read the last number as the rtt
            l_txt = line.strip()
            if l_txt[-1] != "-":
                rtt = l_txt.rsplit(" ", 1)[1]
                print(rtt)
except FileNotFoundError:
    print("Error: The file '../p3-425/425-r.txt' was not found.")