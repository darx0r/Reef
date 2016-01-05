

# Reef ![](images/ReefFish.png)

Reef is an IDAPython plugin for finding cross references (Xrefs) _from_ a function. Each Xref is represented by direction, type, addres and disassembly text, as in the IDA builtin Xref to functionality.


## Reef by Example

```C
#include <stdio.h>

void bar()
{
	printf("hello from bar\n");
}

void foo()
{
	wprintf(L"hello from foo\n");
	bar();
}

void foo2()
{
	wprintf(L"hello from foo2\n");
	bar();
}

void main()
{
	printf("hello from main\n");
	foo();
	foo2();

	getchar();
}
```

I put the cursor on the main function and hit Shift+x.
We get the following Reef output:

![Example Output](examples/images/example_0_output.png)

Notice that each Xref is clickable !
:)

## Requirements

- IDA (Hex Rays Interactive Disassembler) version >= 6.1 with IDAPython
- tested on IDA 6.1.1 (Tell me about your experience on higher versions!)

## Installation

1. Copy src/Reef.py file to the plugins directory of IDA (%IDAPATH%\plugins) 
and restart IDA.

2. You are ready to go :)

## Usage and Menus

load your favourite binary with IDA.
To find Xrefs from the current function, focus on any line in the function disassembly and
hit **Shift+x**.

Reef can also be found in Edit/Plguins/Reef menu.


-
Icons made by <a href="http://www.freepik.com" title="Freepik">Freepik</a> from <a href="http://www.flaticon.com" title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0">CC BY 3.0</a>
