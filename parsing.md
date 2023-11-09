## Notes

in order to maintain simplicity, the sea-parser uses simple parsing methods:

- Tokenizing up-front

	By tokenizing up-front we do not have to worry about whitespace as we are going through the parser


- Bounded Expressions

	Since sea is supposed to be a toy-language, not a production one, the AST is not extendable
	outside of modifying the source-code directly.

## Features

The sea-parser was built as a toy-language to be compiled to the little-man-stack-machine.
 - Built to be similar to the `C` programming language (which it is also written in)
 - Built only to support simple operations
 - Not turing complete (we'll see why)

### Differences

- No forward-declarations. In C, functions be declared before they can be called in other functions. 
	for simplicity's sake, the sea compiler performs hoisting instead; this means that functions are available no matter which
	order they are defined in.

- No structures, unions, or enums. Due to the general size of these constructs, and the little-man-stack-machines limited 100 bytes of memory,
	supporting these constructs just isn't worth the size-constraints of the machine.

- No goto instructions or labels for simplicity. Although possible, these constructs are rarely used even in C development and are once again
	omitted due to the simplicity constraints.

- No statics. Due to the fact that the little-man-stack-machine is, at this time, only built to support singular files, static variables are not of
	much use to us.

### Builtins

- In order to provide some functionality that isn't available purely with syntax, the sea-compiler allows `extern` declarations for the following functions: `void print(int)`, `int scan(void)`, and `void exit(int)`

## AST

The sea parser has three distinctions for ast-elements: expressions, statements, and declarations.


## Developers (notes)

The parser has what I think is a somewhat unique parsing style. Each parse-function takes a pointer to its output and returns an int to indicate the result of the parsing. The function should return 1 if parsing succeeded and 0 otherwise. Generally, all syntax items should support and error-kind so that all parsing functions can return 0 if and only if they do not modify the index in the parser. 
