# Setup and Testing Guide: The Absolute Beginner's Guide to Our Virtual Network


**Has to be done in Linux os**
**Use Virtual Machine**

We are going to create a **virtual mini-internet** inside your computer. This mini-internet will have a victim, a normal user, an attacker, and a smart security guard (our project). We are going to launch a simulated attack to see if our security guard can catch it and stop it.

Whenever you see a gray box with text starting with `sudo` or `pip3`, that is a **command**. You will need to copy that text, paste it into your computer's "Terminal" application, and press **Enter** to run it.

---

## 1. Getting Your Computer Ready (Prerequisites)

Before we build our virtual world, we need to install the basic building blocks. Think of this like buying the materials before building a house.

1. **Open your Terminal:** 
   - You can find the Terminal application by searching your computer's apps (for example, searching "Terminal" in the Ubuntu menu or macOS Spotlight).
2. **Install the building materials:**
   Copy the following two lines of text, paste them into your Terminal, and press Enter. (Your computer might ask for your password. When you type your password, the screen won't show any little stars or dots—that's normal! Just type it and press Enter.)

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch iperf hping3 python3-pip
```

*What did we just do?* We asked your computer to download `mininet` (which builds our virtual computers), `openvswitch` (our virtual router internet connection), and some tools to generate digital traffic.

## 2. Installing the "Blueprint" Ingredients

Now that we have the basic building blocks, we need to add the specific ingredients for our "smart security guard" project. 

1. **Go to the project folder:** 
   You need to tell the Terminal to look inside the folder where you saved this project. Let's assume you saved it in a folder called `mpclient` on your computer.

```bash
cd /coding/mpclient
```

2. **Install the Python tools:**
   Python is the programming language our security guard uses to think. We need to install its dictionary of words.

```bash
pip3 install -r requirements.txt
```

---

## 3. Starting the Digital World

Now it's time to bring our virtual internet to life and turn on our security guard! This project comes with an automatic start button.

**Run the start command:**

```bash
sudo bash run_demo.sh
```

**What is happening right now?**
Your computer is automatically doing several things:
1. It is waking up our security guard (the "SDN Controller").
2. It is creating 3 virtual computers: 
   - `h1`: The Bad Guy
   - `h2`: The Victim Server
   - `h3`: The Normal User
3. It connects them all together using a virtual junction box (`s1`). 

Your terminal prompt will change to say `mininet>`. This means you are now "inside" the simulation and giving commands to the virtual network!

---

## 4. The Fun Part: Testing the Attack

Let's test if the network is working, create some normal traffic, and then launch an attack! Make sure you are typing these commands into the `mininet>` prompt.

### Step A: Are we connected?
Let's make sure everyone can talk to each other. Type this and press Enter:

```bash
pingall
```
*You should see a message saying 0% dropped. Everyone is connected!*

### Step B: Start "Normal" Everyday Traffic
Imagine normal people browsing a website. We will set up the victim (`h2`) to receive data, and tell the normal user (`h3`) to start sending data.

Type this to start the victim holding the door open:
```bash
h2 iperf -s -u &
```

Type this to make the normal user start sending normal, safe data:
```bash
h3 iperf -c 10.0.0.2 -t 60 &
```
*Wait about 10 seconds. The security guard is learning what "normal" looks like.*

### Step C: Launch the Flood Attack!
Now, let's pretend to be the attacker (`h1`). We are going to bombard the Victim (`h2`) with so much junk data that it gets overwhelmed.

```bash
h1 ping -f 10.0.0.2 &
```
*This command fires packets of data as fast as the computer possibly can.*

### Step D: Did the Security Guard Notice?
Our system is designed to notice when one person is sending *way too much* data compared to normal. Let's ask the virtual junction box (`s1`) what its current rules are. 

```bash
s1 ovs-ofctl dump-flows s1
```

**Look closely at the text output.** You are looking for a line that says `actions=drop`. If you see that, **Congratulations!** It means our security guard noticed the attacker (`h1`) acting badly, flagged them, and locked their traffic out to save the victim! 

---

## 5. Shutting Down and Seeing the Results 

Once you are done playing, you can close the simulation.

Type `exit` and press Enter to leave the `mininet>` world. The system will automatically clean up the virtual computers and put things back to normal.

### Generating the Report Cards (Graphs)

While the simulation was running, our security guard was taking notes about everything that happened. We can turn those notes into beautiful graphs to put in a report.

**Type this back in your normal terminal to generate the visual graphs:**
```bash
python3 analysis/plot_stats.py
```
*(This will put image files in the `logs/` folder of your project, showing exactly when the attack started and when the system dropped it!)*

**Type this to calculate exactly how fast the guard reacted:**
```bash
python3 analysis/evaluate.py --attacker 10.0.0.1
```
*(This will tell you exactly how many seconds it took to spot the attacker.)*
