%option nostdinit noyywrap never-interactive full ecs
%option 8bit nodefault perf-report perf-report
%option noinput
%x COMMAND HELP STRING PARAM
%{
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lkc.h"

#define START_STRSIZE	16

static struct {
	struct file *file;
	int lineno;
} current_pos;

static char *text;
static int text_size, text_asize;

struct buffer {
	struct buffer *parent;
	YY_BUFFER_STATE state;
};

struct buffer *current_buf;

static int last_ts, first_ts;

static void zconf_endhelp(void);
static void zconf_endfile(void);

static void new_string(void)
{
	text = xmalloc(START_STRSIZE);
	text_asize = START_STRSIZE;
	text_size = 0;
	*text = 0;
}

static void append_string(const char *str, int size)
{
	int new_size = text_size + size + 1;
	if (new_size > text_asize) {
		new_size += START_STRSIZE - 1;
		new_size &= -START_STRSIZE;
		text = realloc(text, new_size);
		text_asize = new_size;
	}
	memcpy(text + text_size, str, size);
	text_size += size;
	text[text_size] = 0;
}

static void alloc_string(const char *str, int size)
{
	text = xmalloc(size + 1);
	memcpy(text, str, size);
	text[size] = 0;
}

static void warn_ignored_character(char chr)
{
	fprintf(stderr,
	        "%s:%d:warning: ignoring unsupported character '%c'\n",
	        current_file->name, yylineno, chr);
}
%}

n	[A-Za-z0-9_-]

%%
	int str = 0;
	int ts, i;

[ \t]*#.*\n	|
[ \t]*\n	{
	current_file->lineno++;
	return T_EOL;
}
[ \t]*#.*


[ \t]+	{
	BEGIN(COMMAND);
}

.	{
	unput(yytext[0]);
	BEGIN(COMMAND);
}


<COMMAND>{
	{n}+	{
		const struct kconf_id *id = kconf_id_lookup(yytext, yyleng);
		BEGIN(PARAM);
		current_pos.file = current_file;
		current_pos.lineno = current_file->lineno;
		if (id && id->flags & TF_COMMAND) {
			zconflval.id = id;
			return id->token;
		}
		alloc_string(yytext, yyleng);
		zconflval.string = text;
		return T_WORD;
	}
	.	warn_ignored_character(*yytext);
	\n	{
		BEGIN(INITIAL);
		current_file->lineno++;
		return T_EOL;
	}
}

<PARAM>{
	"&&"	return T_AND;
	"||"	return T_OR;
	"("	return T_OPEN_PAREN;
	")"	return T_CLOSE_PAREN;
	"!"	return T_NOT;
	"="	return T_EQUAL;
	"!="	return T_UNEQUAL;
	"<="	return T_LESS_EQUAL;
	">="	return T_GREATER_EQUAL;
	"<"	return T_LESS;
	">"	return T_GREATER;
	\"|\'	{
		str = yytext[0];
		new_string();
		BEGIN(STRING);
	}
	\n	BEGIN(INITIAL); current_file->lineno++; return T_EOL;
	({n}|[/.])+	{
		const struct kconf_id *id = kconf_id_lookup(yytext, yyleng);
		if (id && id->flags & TF_PARAM) {
			zconflval.id = id;
			return id->token;
		}
		alloc_string(yytext, yyleng);
		zconflval.string = text;
		return T_WORD;
	}
	#.*	/* comment */
	\\\n	current_file->lineno++;
	[[:blank:]]+
	.	warn_ignored_character(*yytext);
	<<EOF>> {
		BEGIN(INITIAL);
	}
}

<STRING>{
	[^'"\\\n]+/\n	{
		append_string(yytext, yyleng);
		zconflval.string = text;
		return T_WORD_QUOTE;
	}
	[^'"\\\n]+	{
		append_string(yytext, yyleng);
	}
	\\.?/\n	{
		append_string(yytext + 1, yyleng - 1);
		zconflval.string = text;
		return T_WORD_QUOTE;
	}
	\\.?	{
		append_string(yytext + 1, yyleng - 1);
	}
	\'|\"	{
		if (str == yytext[0]) {
			BEGIN(PARAM);
			zconflval.string = text;
			return T_WORD_QUOTE;
		} else
			append_string(yytext, 1);
	}
	\n	{
		printf("%s:%d:warning: multi-line strings not supported\n", zconf_curname(), zconf_lineno());
		current_file->lineno++;
		BEGIN(INITIAL);
		return T_EOL;
	}
	<<EOF>>	{
		BEGIN(INITIAL);
		yylval.string = text;
		return T_WORD_QUOTE;
	}
}

<HELP>{
	[ \t]+	{
		ts = 0;
		for (i = 0; i < yyleng; i++) {
			if (yytext[i] == '\t')
				ts = (ts & ~7) + 8;
			else
				ts++;
		}
		last_ts = ts;
		if (first_ts) {
			if (ts < first_ts) {
				zconf_endhelp();
				return T_HELPTEXT;
			}
			ts -= first_ts;
			while (ts > 8) {
				append_string("        ", 8);
				ts -= 8;
			}
			append_string("        ", ts);
		}
	}
	[ \t]*\n/[^ \t\n] {
		current_file->lineno++;
		zconf_endhelp();
		return T_HELPTEXT;
	}
	[ \t]*\n	{
		current_file->lineno++;
		append_string("\n", 1);
	}
	[^ \t\n].* {
		while (yyleng) {
			if ((yytext[yyleng-1] != ' ') && (yytext[yyleng-1] != '\t'))
				break;
			yyleng--;
		}
		append_string(yytext, yyleng);
		if (!first_ts)
			first_ts = last_ts;
	}
	<<EOF>>	{
		zconf_endhelp();
		return T_HELPTEXT;
	}
}

<<EOF>>	{
	if (current_file) {
		zconf_endfile();
		return T_EOL;
	}
	fclose(yyin);
	yyterminate();
}

%%
void zconf_starthelp(void)
{
	new_string();
	last_ts = first_ts = 0;
	BEGIN(HELP);
}

static void zconf_endhelp(void)
{
	zconflval.string = text;
	BEGIN(INITIAL);
}

char **overlays;
int overlay_count;

static void zconf_init_overlays(void)
{
	static int initialized;
	char *env, *elem;

	if (initialized)
		return;
	initialized = 1;

	overlays = xmalloc(2 * sizeof(*overlays));
	overlays[0] = "";
	overlays[1] = NULL;
	overlay_count = 2;

	env = getenv(SRCTREE);
	if (env && strcmp(env, "."))
		overlays[1] = env;

	env = getenv("KERNEL_OVERLAYS");
	if (!env)
		return;
	env = xstrdup(env);

	for (;;) {
		elem = strtok(env, " ");
		if (!elem)
			break;
		env = NULL;

		overlays = xrealloc(overlays, (overlay_count + 1) * sizeof(*overlays));
		overlays[overlay_count] = elem;
		overlay_count++;
	}
}

/*
 * Try to open specified file with following names:
 * ./name
 * $(srctree)/name
 * The latter is used when srctree is separate from objtree
 * when compiling the kernel.
 * Return NULL if file is not found.
 */
FILE *zconf_fopen(const char *name, int init_overlay_id, int *found_overlay_id, const char **found_name)
{
	int i;
	char fullname[PATH_MAX+1];
	FILE *fp;

	zconf_init_overlays();

	for (i = init_overlay_id; i < overlay_count; i++) {
		if (!overlays[i])
			continue;
		if (overlays[i][0])
			sprintf(fullname, "%s/%s", overlays[i], name);
		else
			strcpy(fullname, name);
		fp = fopen(fullname, "r");
		if (fp) {
			if (found_overlay_id)
				*found_overlay_id = i;
			if (found_name) {
				if (i < 2)
					*found_name = name;
				else
					*found_name = fullname;
				*found_name = xstrdup(*found_name);
			}
			return fp;
		}
	}

	return NULL;
}

void zconf_initscan(const char *name)
{
	int found_overlay_id;

	zconf_init_overlays();

	yyin = zconf_fopen(name, 0, &found_overlay_id, NULL);
	if (!yyin) {
		printf("can't find file %s\n", name);
		exit(1);
	}

	current_buf = xmalloc(sizeof(*current_buf));
	memset(current_buf, 0, sizeof(*current_buf));

	/*
	 * file_lookup can't find name, so won't free it, so no need to
	 * duplicate the allocation
	 */
	current_file = file_lookup(name, found_overlay_id, name);
	current_file->lineno = 1;
}

static void zconf_nextfile_imp(int init_overlay_id, const char *name, int must_exist)
{
	FILE *fp;
	struct file *file;
	struct buffer *buf;
	int found_overlay_id;
	const char *found_name;

	if (current_buf)
		current_buf->state = YY_CURRENT_BUFFER;

	fp = zconf_fopen(name, init_overlay_id, &found_overlay_id, &found_name);
	if (!fp) {
		if (must_exist) {
			printf("%s:%d: can't open file \"%s\"\n",
			    zconf_curname(), zconf_lineno(), name);
			exit(1);
		}
		return;
	}

	yyin = fp;
	yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));

	buf = xmalloc(sizeof(*buf));
	memset(buf, 0, sizeof(*buf));
	buf->parent = current_buf;
	current_buf = buf;

	file = file_lookup(found_name, found_overlay_id, name);
	file->lineno = 1;
	file->parent = current_file;
	current_file = file;
}

void zconf_nextfile(const char *name)
{
	const char *file_name = sym_expand_string_value(name);
	struct file *iter;

	for (iter = current_file; iter; iter = iter->parent ) {
		if (!strcmp(file_name, iter->logical_name) ) {
			printf("%s:%d: recursive inclusion detected. "
			       "Inclusion path:\n  current file : '%s'\n",
			       zconf_curname(), zconf_lineno(),
			       zconf_curname());
			iter = current_file->parent;
			while (iter) {
				printf("  included from: '%s:%d'\n",
				       iter->name, iter->lineno-1);
				iter = iter->parent;
			}
			exit(1);
		}
	}

	zconf_nextfile_imp(0, file_name, 1);
}

static void zconf_endfile(void)
{
	struct buffer *parent;
	struct file *prev_file;

	prev_file = current_file;
	current_file = current_file->parent;

	parent = current_buf->parent;
	if (parent) {
		fclose(yyin);
		yy_delete_buffer(YY_CURRENT_BUFFER);
		yy_switch_to_buffer(parent->state);
	}
	free(current_buf);
	current_buf = parent;

	if (prev_file->overlay_id < overlay_count - 1)
		zconf_nextfile_imp(prev_file->overlay_id + 1, xstrdup(prev_file->logical_name), 0);
}

int zconf_lineno(void)
{
	return current_pos.lineno;
}

const char *zconf_curname(void)
{
	return current_pos.file ? current_pos.file->name : "<none>";
}
