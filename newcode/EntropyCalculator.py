from __future__ import division
import math

def entropys(string):
    "Calculates the Shannon entropy of a string"
    # get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    # calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def entropy_ideal(length):
    "Calculates the ideal Shannon entropy of a string with given length"
    prob = 1.0 / length
    return -1.0 * length * prob * math.log(prob) / math.log(2.0)
    
def hist(source):
    hist = {}; l = 0;
    for e in source:
        l += 1
        if e not in hist:
            hist[e] = 0
        hist[e] += 1
    return (l,hist)
 
def entropy(hist,l):
    elist = []
    for v in hist.values():
        c = v / l
        elist.append(-c * math.log(c ,2))
    return sum(elist)
 
def printHist(h, l):
    flip = lambda (k,v) : (v,k)
    h = sorted(h.iteritems(), key = flip)
    print 'Sym\thi\tfi\tInf'
    for (k,v) in h:
        print '%s\t%f\t%f\t%f'%(k,v,v/l,-math.log(v/l, 2))