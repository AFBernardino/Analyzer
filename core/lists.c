#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "lists.h"

node_str * create_string_list() {
	node_str * string_list = (node_str *) malloc(sizeof(node_str));

	if (string_list == NULL) {
		fprintf(stdout, "Error creating list of strings.");
		return NULL;
	}

	string_list->str = NULL;
	string_list->next = NULL;

	return string_list;
}

int add_string(node_str * head, char * str) {
	node_str * current = head;

	if (head == NULL) {
		fprintf(stdout, "NULL list of strings received.");
		return -1;
	}
	
	while (current->next != NULL) {
		current = current->next;
	}

	// check if current element is already empty (i.e. first element)
	if (current->str == NULL) {
		current->str = str;
		return 0;
	}

    current->next = (node_str *) malloc(sizeof(node_str));

	// verify if node was successfully created
	if (current->next == NULL) {
		fprintf(stdout, "Error creating next element on list of strings.");
		return -1;
	}

    current->next->str = str;
    current->next->next = NULL;

	return 0;
}

void print_string_list(node_str * head) {
	node_str * current = head;
	while (current != NULL) {
		if (current->str != NULL) {
			fprintf(stdout, "%s\n", current->str);
		}
		current = current->next;
	}
}

bool is_empty(node_str * head) {
	if (head == NULL) {
		return true;
	} else if (head->str == NULL && head->next == NULL) {
		return true;
	}
	return false;
}

void free_string_list(node_str * head) {
	node_str * current = head;
	node_str * to_free = head;
	while (current != NULL) {
		current = current->next;
		free(to_free->str);
		free(to_free);
		to_free = current;
	}
}

pattern * create_pattern_struct() {
	pattern * head = NULL;

	// allocate memory for pattern struct
	head = (pattern *) malloc(sizeof(pattern));
	if (head == NULL) {
		fprintf(stdout, "Error creating pattern struct.");
		return NULL;
	}

	// allocate memory for lists of strings
	head->vuln_name = NULL;
	head->entry_points = create_string_list();
	head->sanit_funcs = create_string_list();
	head->sinks = create_string_list();

	return head;
}

node_pattern * create_pattern_list() {
	node_pattern * pattern_list = (node_pattern *) malloc(sizeof(node_pattern));

	if (pattern_list == NULL) {
		fprintf(stdout, "Error creating list of patterns.");
		return NULL;
	}

	pattern_list->pattern = NULL;
	pattern_list->next = NULL;

	return pattern_list;
}

int add_pattern(node_pattern * head, pattern * pattern) {
	node_pattern * current = head;

	if (head == NULL) {
		fprintf(stdout, "NULL list of patterns received.");
		return -1;
	}

	while (current->next != NULL) {
		current = current->next;
	}

	// check if current element is already empty (i.e. first element)
	if (current->pattern == NULL) {
		current->pattern = pattern;
		return 0;
	}

    current->next = (node_pattern *) malloc(sizeof(node_pattern));

	// verify if node was successfully created
	if (current->next == NULL) {
		fprintf(stdout, "Error creating next element on list of patterns.");
		return -1;
	}

    current->next->pattern = pattern;
    current->next->next = NULL;

    return 0;
}

void free_pattern_list(node_pattern * head) {
	node_pattern * current = head;
	node_pattern * to_free = head;
	while (current != NULL) {
		current = current->next;
		free(to_free->pattern->vuln_name);
		free_string_list(to_free->pattern->entry_points);
		free_string_list(to_free->pattern->sanit_funcs);
		free_string_list(to_free->pattern->sinks);
		free(to_free->pattern);
		free(to_free);
		to_free = current;
	}
}

