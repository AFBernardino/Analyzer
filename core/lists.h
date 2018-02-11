#ifndef _LISTS_
#define _LISTS_

// linked list of strings
typedef struct node_str{
	char * str;
	struct node_str * next;
} node_str;

// pattern for vulnerabilities struct
typedef struct {
	char * vuln_name;					// vulnerability name
	struct node_str * entry_points;		// entry points
	struct node_str * sanit_funcs;		// sanitization functions
	struct node_str * sinks;			// sensitive sinks
} pattern;

// linked list of patterns
typedef struct node_pattern{
	pattern * pattern;
	struct node_pattern * next;
} node_pattern;

// create linked list of strings and returns a pointer to the head
node_str * create_string_list();

// add new element to list of strings
int add_string(node_str * head, char * str);

// print list of strings
void print_string_list(node_str * head);

// return true if the input is an empty list of strings
bool is_empty(node_str * head);

// free entire list of strings
void free_string_list(node_str * head);

// create pattern struct and return the pointer to the head
pattern * create_pattern_struct();

// create linked list of patterns and returns a pointer to the head
node_pattern * create_pattern_list();

// add new element to list of patterns
int add_pattern(node_pattern * head, pattern * pattern);

// free entire list of patterns
void free_pattern_list(node_pattern * head);

#endif
