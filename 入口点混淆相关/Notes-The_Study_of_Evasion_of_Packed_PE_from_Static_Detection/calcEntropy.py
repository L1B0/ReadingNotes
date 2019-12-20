from math import log

f = open('../ransomware/file-decrypted-unpacked.exe','rb').read()
s = len(f)
s = float(s)
l = [0]*256
for i in f:
	l[ord(i)] += 1
l = [i/s for i in l]
print sum(l)
for i in range(len(l)):
	if l[i] == 0.0:
		continue
	l[i] = -(l[i]*log(l[i],2))
print sum(l)