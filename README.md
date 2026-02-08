# Ethical Considerations
Remember that hacking into devices without permission is illegal and unethical.\
Always ensure you have the necessary permissions and are conducting these activities in a\
controlled environment for educational or security assessment purposes.

# Computing101
## Memory manipulation

<details>
<summary style="cursor:pointer">Loading from memory</summary>
  
-  To access the memory contents at memory address 31337, you can do [31337] for the memory adress:
```bash
.intel_syntax noprefix
.global _start
_start:
mov rdi, [31337]
mov rax, 60
syscall
```
then:  hacker@dojo:$ as -o programm.o programm.s\
then:  hacker@dojo:$ ld -o programm programm.o\
then:  hacker@dojo:$ programm

- mov -- mov DOES NOT move the memory content out, from one memory adress into the next one >> it COPYS it - both memory adresses have the same content!
- as -- The "as" tool reads in program.s, assembles it into binary code, and outputs an object file called program.o.\
- ld -- Linking Object Files into an Executable. In a typical development workflow, source code is compiled and assembly is assembled to object files, and there are typically many of these (generally,
 each source code file in a program compiles into its own object file). These are then linked together into a single executable. Even if there is only one
 file, we still need to link it, to prepare the final executable. This is done with the ld (stemming from the term "link editor") command.\

- When the CPU executes this instruction, it of course understands that 31337 is an address, not a raw value. If you think of the instruction as a person
telling the CPU what to do, and we stick with our "houses on a street" analogy, then instead of just handing the CPU data, the instruction/person points 
at a house on the street. The CPU will then go to that address, ring its doorbell, open its front door, drag the data that's in there out, and put it into
rdi. Thus, the 31337 in this context is the memory address and serves to point to the data stored at that memory address. After this instruction executes, 
the value stored in rdi will be 42!
</details>


<details>
<summary style="cursor:pointer">More loading practice</summary>
  
-  To access the memory contents at memory address 31337, you can do [31337] for the memory adress:
```bash
.intel_syntax noprefix
.global _start
_start:
mov rdi, [31337]
mov rax, 60
syscall
```
then:  hacker@dojo:$ as -o programm.o programm.s\
then:  hacker@dojo:$ ld -o programm programm.o\
then:  hacker@dojo:$ programm

- mov -- mov DOES NOT move the memory content out, from one memory adress into the next one >> it COPYS it - both memory adresses have the same content!
- as -- The "as" tool reads in program.s, assembles it into binary code, and outputs an object file called program.o.\
- ld -- Linking Object Files into an Executable. In a typical development workflow, source code is compiled and assembly is assembled to object files, and there are typically many of these (generally,
 each source code file in a program compiles into its own object file). These are then linked together into a single executable. Even if there is only one
 file, we still need to link it, to prepare the final executable. This is done with the ld (stemming from the term "link editor") command.\

- When the CPU executes this instruction, it of course understands that 31337 is an address, not a raw value. If you think of the instruction as a person
telling the CPU what to do, and we stick with our "houses on a street" analogy, then instead of just handing the CPU data, the instruction/person points 
at a house on the street. The CPU will then go to that address, ring its doorbell, open its front door, drag the data that's in there out, and put it into
rdi. Thus, the 31337 in this context is the memory address and serves to point to the data stored at that memory address. After this instruction executes, 
the value stored in rdi will be 42!
</details>

<details>
<summary style="cursor:pointer">Dereferencing pointers</summary>
  
```bash
hacker@memory~dereferencing-pointers:~$ cd assambly/memory/
hacker@memory~dereferencing-pointers:~/assambly/memory$ cp loadingfrommemory.s dereferencing.s
hacker@memory~dereferencing-pointers:~/assambly/memory$ nano dereferencing.s
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rax]
mov rax, 60
syscall
---
hacker@memory~dereferencing-pointers:~/assambly/memory$ as -o dereferencing.o dereferencing.s 
hacker@memory~dereferencing-pointers:~/assambly/memory$ ld -o dereferencing dereferencing.o
hacker@memory~dereferencing-pointers:~/assambly/memory$ /challenge/check dereferencing

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by rax (value 145) to succeed!

hacker@memory~dereferencing-pointers:/home/hacker/assambly/memory$ /tmp/your-program
hacker@memory~dereferencing-pointers:/home/hacker/assambly/memory$ echo $?
145
hacker@memory~dereferencing-pointers:/home/hacker/assambly/memory$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{
```
</details>


<details>
<summary style="cursor:pointer">Dereferencing yourself</summary>
  
In the previous level, you dereferenced rax to read data into rdi. The interesting thing here is that our choice of rax was pretty arbitrary. We could have used any other pointer, even rdi itself! Nothing stops you from dereferencing a register to overwrite its own content with the dereferenced value!

For example, here is us doing this exact thing with rax. I've annotated each line with comments:
```bash
mov [133700], 42
mov rax, 133700  # after this, rax will be 133700
mov rax, [rax]   # after this, rax will be 42
```
Throughout this snippet, rax goes from being used as a pointer to being used to hold the data that's been read from memory. The CPU makes this all work!

In this challenge, you'll explore this concept. Rather than initializing rax, as before, we've made rdi the pointer to the secret value! You'll need to dereference it to load that value into rdi, then exit with that value as the exit code. Good luck!
```bash
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rdi]
mov rax, 60
syscall
```
</details>


<details>
<summary style="cursor:pointer">Dreferencing with offset</summary>
So now you can dereference pointers in memory like a pro! But pointers don't always point directly at the data you need.\
Sometimes, for example, a pointer might point to a collection of data (say, an entire book),\
and you'll need to reference partway into this collection for the specific data you need.

For example, if your pointer (say, rdi) points to a sequence of numbers in memory, as so:\
If you want the second number of that sequence, you could do:
```bash
mov rax, [rdi+1]
```
Wow, super simple! In memory terms, we call these number slots bytes: each memory address represents a specific byte of memory. The above example is accessing memory 1 byte after the memory address pointed to by rdi. In memory terms, we call this 1 byte difference an offset, so in this example, there is an offset of 1 from the address pointed to by rdi.

Let's practice this concept. As before, we will initialize rdi to point at the secret value, but not directly at it. This time, the secret value will have an offset of 8 bytes from where rdi points, something analogous to this:

```bash
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rdi+8]
mov rax, 60
syscall
```
</details>

<details>
<summary style="cursor:pointer">Stored Adresses</summary>
Pointers can get even more interesting! Imagine that your friend lives in a different house on your street. Rather than remembering their address, you might write it down, and store the paper with their house address in your house. Then, to get data from your friend, you'd need to point the CPU at your house, have it go in there and find the friend's address, and use that address as a pointer to their house.

Similarly, since memory addresses are really just values, they can be stored in memory, and retrieved later! Let's explore a scenario where we store the value 133700 at the address 123400, and store the value 42 at the address 133700. Consider the following instructions:
```bash
mov rdi, 123400    # after this, rdi becomes 123400
mov rdi, [rdi]     # after this, rdi becomes the value stored at 123400 (which is 133700)
mov rax, [rdi]     # here we dereference rdi, reading 42 into rax!
```
Wow! This storing of addresses is extremely common in programs. Addresses and data are stored, loaded, moved around, and, sometimes, mixed up with each other! When that happens, security issues can arise, and you'll romp through many such issues during your pwn.college journey.

For now, let's practice dereferencing an address stored in memory. I'll store a secret value at a secret address, then store that secret address at the address 567800. You must read the address, dereference it, get the secret value, and then exit with it as the exit code. You got this!

```bash
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rdi, [567800]
mov rdi, [rdi]
mov rax, 60
syscall
```
</details>

<details>
<summary style="cursor:pointer">Double dereferencing</summary>
Let's put those last two together. In this challenge, we stored our SECRET_VALUE in memory at the address SECRET_LOCATION_1,
then stored SECRET_LOCATION_1 in memory at the address SECRET_LOCATION_2. Then, we put SECRET_LOCATION_2 into rax! The result
looks something like this, using 123400 for SECRET_LOCATION_1 and 133700 for SECRET_LOCATION_2 (not, in the real challenge,
these values will be different and hidden from you!)

Here, you will need to perform two memory reads: one dereferencing rax to read SECRET_LOCATION_1 from the location that rax is pointing to
(which is SECRET_LOCATION_2), and the second one dereferencing whatever register now holds SECRET_LOCATION_1 to read SECRET_VALUE into rdi,
so you can use it as the exit code!

That sounds like a lot, but you've done basically all of this already. Go put it together!

```bash
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rax]
mov rdi, [rdi]
mov rax, 60
syscall
```

```bash
hacker@memory~double-dereference:~$ cd assambly/memory/
hacker@memory~double-dereference:~/assambly/memory$ touch doublederefer.s
hacker@memory~double-dereference:~/assambly/memory$ nano doublederefer.s 
hacker@memory~double-dereference:~/assambly/memory$ as -o doublederefer.o doublederefer.s
hacker@memory~double-dereference:~/assambly/memory$ ld -o doublederefer doublederefer.o
hacker@memory~double-dereference:~/assambly/memory$ /challenge/check doublederefer

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by a chain of pointers starting at rax!

hacker@memory~double-dereference:/home/hacker/assambly/memory$ /tmp/your-program
hacker@memory~double-dereference:/home/hacker/assambly/memory$ echo $?
62
hacker@memory~double-dereference:/home/hacker/assambly/memory$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{
```
</details>

<details>
<summary style="cursor:pointer">Double dereferencing</summary>
  
```bash
--- nano
.intel_syntax noprefix
.global _start
_start:
mov rax, [rdi]
mov rax, [rax]
mov rdi, [rax]
mov rax, 60
syscall
```
</details>

## Hello Hackers
