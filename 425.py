import matplotlib.pyplot as plt
print("Test")

# create hash table with key = first segment and vale == array {durr, rtt}
dict = {}

try:
    with open('../p3-425/425-r.txt', 'r') as file:
        for line in file:
            # if 2nd to last character is not -, read the last number as the rtt
            l_txt = line.strip()
            if l_txt[-1] != "-":
                rtt = l_txt.rsplit(" ", 1)[1]
                str_arr = l_txt.split(" ")
                id = str_arr[0] + " " + str_arr[1]  + " " + str_arr[2] + " " + str_arr[3]
                print(id)
                dict[id] = [rtt, 0]
                #print(rtt)
except FileNotFoundError:
    print("Error: The file '../p3-425/425-r.txt' was not found.")

try:
    with open('../p3-425/425-n.txt', 'r') as file:
        for line in file:
            # if line has 'T'
            l_txt = line.strip()
            if "T" in l_txt:
                # get the duration
                dur = l_txt.rsplit(" ")[6]
                str_arr = l_txt.split(" ")
                id = str_arr[0] + " " + str_arr[1]  + " " + str_arr[2] + " " + str_arr[3]
                #print(str_arr)
                try:
                    dict[id] = [dict[id][0], dur]
                except KeyError:
                    print("Key error on " + id)
                #print(dur)
except FileNotFoundError:
    print("Error: The file '~/p3-425/425-r.txt' was not found.")

#print(dict)
print(len(dict))

rtts = [v[0] for v in dict.values()]
durations = [v[1] for v in dict.values()]


plt.scatter(rtts, durations)
plt.xlabel("RTT (seconds)")
plt.ylabel("Flow Duration (seconds)")
plt.title("Relationship between RTT and Flow Duration")
plt.grid(True)
plt.show()