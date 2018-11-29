Group 13: Luke Welton, Jesse Roach, Bryant Kelley

# Introduction
This project builds off of Lab 2, which implemented a ring of communication between a Master and various Slaves.
In this project, we expand it to now allow for actually sending messages throughout the ring.
The Master is written in C++, and the Slave is written in Python.

# Functionality
In the previous lab, a Master is created was a TCP Server, allowing multiple UDP Clients to join as Slaves in a ring formation.

In this lab, we introduce the ability to send messages between each node in the ring.
Each node prompts the user for a message and a ring ID to send the message to.
It then sends the message throughout the ring, and if a node with the given ID is in the ring, it displays the message.
If the message returns to the node after sending it, it discards the message.

# Compiling
To compile the Master, you type `g++ Master.cpp -o Master -std=c++11` into the command line of a Linux machine with G++.
The std tag is necessary, as some of our code is written with functionality from C++ 2011.

As the Slave is written in Python, a scripting language, no compilation is necessary.

# Executing
To execute the now-compiled Master, you enter `./Master <MasterPort#>`, substituting `<MasterPort#>` with the chosen port number.
As we are Group 13, we have been using 10075, but many other port numbers will work.

To execute the Slave, you enter `python Slave.py <MasterHostname> <MasterPort#>`, substituting `<MasterHostname>` with the hostname of the Master and `<MasterPort#>` with the same port number used with the Master.

# Results
Our programs appear to run correctly on the tux machines on separate hosts.
