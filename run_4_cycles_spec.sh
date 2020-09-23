#!/bin/bash

./rampspec.py -H 10.1.246.117 -r 'Ws25.0,l1;Rr30,s55;Ws55,l1;Ht1;Rr50.0,s-20.0;Ws-20,l1,d;Ht1,d;Rr30.0,s19.0,d;Ws19.0,l1,d;Rs55,r30;Ws55,l1;Ht1;Rr50.0,s-20.0;Ws-20,l1,d;Ht1,d;Rr30.0,s19.0,d;Ws19.0,l1,d;[2#Rs55,r30;Ws55,l1;Ht1;Rr50.0,s-20.0;Ws-20,l1,d;Ht1,d;Rr30,s19.0,d;Ws19.0,l1,d;];Rr30,s30;Ws30,l1;Ht2'

#First cycle: 
#1 hour to 55 degrees
#1 hour dwell
#1.5 hour to -20
#1 hour dwell

# cycle:
#total time first cycle: 4.5 hours
#second cycle:
#2.5 hour to 55 degrees
#1 hour dwell
#1.5 hour to -20
#1 hour dwell

#wait 8 hours

#repeat above cycle again 2 times

