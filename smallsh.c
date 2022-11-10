#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

/* Ariel Rosenthal -- SMALLSH */

/* This shell needs to....
Provide a prompt for running commands
Handle blank lines and comments, which are lines beginning with the # character
Provide expansion for the variable $$
Execute 3 commands exit, cd, and status via code built into the shell
Execute other commands by creating new processes using a function from the exec family of functions
Support input and output redirection
Support running commands in foreground and background processes
Implement custom handlers for 2 signals, SIGINT and SIGTSTP
*/

/* Abbreviations:
arg ~ argument
bg ~ background
cmd ~ command
eq ~ equal
exe ~ execute
fg ~ foreground
iter ~ iterator
subs ~ substitute
var ~ variable
*/

/* Sources for Shell Overall:
https://www.geeksforgeeks.org/making-linux-shell-c/
https://brennan.io/2015/01/16/write-a-shell-in-c/
http://www.dmulholl.com/lets-build/a-command-line-shell.html
https://danishpraka.sh/2018/01/15/write-a-shell.html
https://www.cs.cornell.edu/courses/cs414/2004su/homework/shell/shell.html
https://www.youtube.com/watch?v=zDjLADJGXFs
https://www.youtube.com/watch?v=pS3rbCW9D9g
https://www.youtube.com/watch?v=uh2FqejQRk8
https://www.youtube.com/watch?v=v-F3YLd6oMw
https://www.youtube.com/watch?v=4jYFqFsu03A
https://www.youtube.com/watch?v=hMU3IL48Z_w
https://www.youtube.com/watch?v=zuegQmMdy8M&t=2s
*/


bool str_eq(const char *s0, const char *s1) {
    return strcmp(s0, s1) == 0;
}

/**
 * This is meant to read a line of text from stdin.
 * Then it returns whether it was successful and the line ends with a new line.
 * Sources used: https://linuxhint.com/read-lines-stdin-c-programming/
 * https://dev-notes.eu/2019/07/Get-a-line-from-stdin-in-C/
 */
bool read_line(size_t size, char *buffer) {
    /*if (fgets(buffer, size))*/
    if (fgets(buffer, size, stdin) == NULL) return false;
    if (buffer[0] == '\0') return false;
    size_t buffer_len = strlen(buffer);
    /*size_t buffer_last = //no*/
    char *buffer_last = &buffer[buffer_len - 1];
    if (*buffer_last != '\n') return false; /*New line*/
    *buffer_last = '\0';
    return true;
}



/****************************************************************
 * A list of strings for command line arguments.
 * It owns strings.
 * Sources Used: https://www.montana.edu/rmaher/ee475_fl04/Command_line.pdf
 * https://stackoverflow.com/questions/5046035/how-to-read-string-from-command-line-argument-in-c
 * 
 */

#define MAX_ARG_N (512 + 1)

struct args {
    size_t n;
    char *a[MAX_ARG_N];
};

void args_init(struct args *args0) {
    args0->n = 0;
}

void args_destroy(struct args *args0) {
    for (size_t i = args0->n; i-- != 0;) free(args0->a[i]);
}

bool args_insert(struct args *args0, char *arg) {
    if (args0->n == MAX_ARG_N) return false;
    args0->a[args0->n] = arg;
    args0->n++;
    return true;
}



/****************************************************************
 * Variables.
 * Source Used: https://byjus.com/gate/variables-in-c/
 */

/** Variable name. It should not be empty. */
const char *const VAR = "$$";

/** This is the length of the variable name */
const size_t VAR_LEN = 2;

/**
 * The length of s after substituting the value for the variable.
 * Sources Used: https://www.freecodecamp.org/news/pointers-in-c-are-not-as-difficult-as-you-think/
 * https://www.guru99.com/c-pointers.html
 * https://www.youtube.com/watch?v=zuegQmMdy8M
 * 
 */
size_t expand_var_len(const char *s, const char *value) {
    size_t value_len = strlen(value);
    size_t len = 0;
    while (true) {
        char *var = strstr(s, VAR);
        /*if ()*/
        if (var == NULL) {
            len += strlen(s);
            break;
        }
        len += var - s + value_len;
        s = var + VAR_LEN;
    }
    return len;
}

/**
 * This returns s where value is substituted for VAR.
 * The returned string is malloced.
 * Sources Used: https://www.se.rit.edu/~swen-250/activities/MicroActivities/C/mu_string_malloc/distrib/index.html
 * https://cboard.cprogramming.com/c-programming/163727-using-malloc-entered-strings.html
 * https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm
 */
char *expand_var(const char *s, const char *value) {
    size_t value_len = strlen(value);
    const size_t result_len = expand_var_len(s, value);
    size_t result_len1 = result_len;
    char *const result = malloc((result_len + 1) * sizeof(char));
    if (result == NULL) return NULL; /*Obviously if the result is NULL, we will return NULL*/
    char *result1 = result;
    while (true) {
        char *var = strstr(s, VAR);
        if (var == NULL) { /*If our var is NULL, we need to handle it*/
            size_t len = strlen(s);
            if (len != result_len1) {
                fputs("internal error: expand_var end\n", stderr); /*error*/
                exit(EXIT_FAILURE);
            }
            memcpy(result1, s, len * sizeof(char));
            result1 += len;
            result1[0] = '\0';
            break;
        }
        size_t len = var - s;
        if (result_len1 < len) { /* If the result length is greater than the length, that's not possible, so we need to handle it*/
            fputs("internal error: expand_var middle\n", stderr); /*error*/
            exit(EXIT_FAILURE);
        }
        memcpy(result1, s, len * sizeof(char));
        result1 += len;
        result_len1 -= len;
        memcpy(result1, value, value_len * sizeof(char));
        result1 += value_len;
        result_len1 -= value_len;
        s = var + VAR_LEN;
    }
    return result;
}



/**
 * A token type is either
 * - a keword (TOKEN_TYPE_BG goes to TOKEN_BG, etc)
 * - a EOF (doesn't go to any string, marks the end of a parsed string)
 * - other (`TOKEN_TYPE_NAME`).
 * Sources Used: https://www.scaler.com/topics/c/tokens-in-c/
 * https://www.educba.com/tokens-in-c/
 * https://www.javatpoint.com/tokens-in-c
 * https://www.geeksforgeeks.org/cc-tokens/
 * 
 */
enum token_type {
    TOKEN_TYPE_EOF,
    TOKEN_TYPE_BG,
    TOKEN_TYPE_IN,
    TOKEN_TYPE_OUT,
    TOKEN_TYPE_NAME
};

/**
 * Keyword tokens. Command arguments, and file paths
 * They can't be keyword tokens because they are handled in a different way when parsing.
 * Sources Used: https://www.guru99.com/c-tokens-keywords-identifier.html
 * https://developerinsider.co/11-command-line-arguments/
 * https://stackoverflow.com/questions/14779112/how-to-compare-strings-in-c-for-a-condition
 * 
 */
#define TOKEN_BG "&"
/*const char*/
const char *const TOKEN_IN = "<";
const char *const TOKEN_OUT = ">";

enum token_type get_token_type(char *s) {
    if (s == NULL) return TOKEN_TYPE_EOF;
    if (str_eq(s, TOKEN_BG)) return TOKEN_TYPE_BG;
    if (str_eq(s, TOKEN_IN)) return TOKEN_TYPE_IN;
    if (str_eq(s, TOKEN_OUT)) return TOKEN_TYPE_OUT;
    return TOKEN_TYPE_NAME;
}

struct token {
    enum token_type type;
    char *s;
};

/** token iterator */
struct token_iter {
    char *strtok_r_state;
    struct token token0;
};

const char *const TOKEN_DELIMITERS = " ";

void token_iter_init(struct token_iter *token_iter0, char *s) {
    token_iter0->strtok_r_state = NULL;
    /*char token_s = */
    char *token_s = strtok_r(s, TOKEN_DELIMITERS, &token_iter0->strtok_r_state);
    struct token *token0 = &token_iter0->token0;
    token0->type = get_token_type(token_s);
    token0->s = token_s;
}

/**
 * The first token in the token stream `token_iter0`.
 */
struct token token_iter_peek(struct token_iter *token_iter0) {
    return token_iter0->token0;
}

/**
 * Takes the first token in the token stream `token_iter0`.
 */
void token_iter_next(struct token_iter *token_iter0) {
    struct token *token0 = &token_iter0->token0;
    if (token0->type != TOKEN_TYPE_EOF) {
        char *token_s = strtok_r(NULL, TOKEN_DELIMITERS,
            &token_iter0->strtok_r_state);
        token0->type = get_token_type(token_s);
        token0->s = token_s;
    }
}



/**
 * This parses an optional TOKEN_BG by taking the token stream token_iter0.
 * Then returns whether there was TOKEN_BG or not.
 */
bool parse_bg(struct token_iter *token_iter0) {
    enum token_type token_type0 = token_iter_peek(token_iter0).type;
    if (token_type0 != TOKEN_TYPE_BG) return false;
    token_iter_next(token_iter0);
    return true;
}

/**
 * Parses an optional TOKEN_TYPE_NAME
 * Then taking the token stream token_iter0.
 * If there was TOKEN_TYPE_NAME, it returns it. Otherwise, it returns NULL.
 * Then returns the string that is inside the string that token_iter0 goes to.
 */
char *parse_optional_name(struct token_iter *token_iter0) {
    struct token token0 = token_iter_peek(token_iter0);
    if (token0.type == TOKEN_TYPE_EOF) return NULL; /*null*/
    if (token0.type != TOKEN_TYPE_NAME) return NULL; /*null*/
    token_iter_next(token_iter0);
    return token0.s;
}
/*note to self... need to handle exit, status and cd*/
/** These are built-in commands for the shell that needed to be included*/
const char *const CMD_EXIT = "exit";
const char *const CMD_STATUS = "status";
const char *const CMD_CD = "cd";

/**
 * Changes the current directory to dir if dir does not equal NULL.
 * Prints an error if changing to dir hasn't been successful.
 * Sources Used: https://www.geeksforgeeks.org/chdir-in-c-language-with-examples/#:~:text=The%20chdir%20command%20is%20a,the%20directory%20specified%20in%20path.
 */
void handle_cd_chdir(char *dir) {
    if (dir != NULL) { /*if the directory is null*/
        if (chdir(dir)) {
            perror("chdir");
        }
    }
}

/**
 * This is meant to parse and execute the command CMD_CD.
 * Sources Used: https://stackoverflow.com/questions/22286708/cd-command-implemented-in-c
 * https://stackoverflow.com/questions/67251953/implement-cd-command-in-c
 */
void handle_cd(const char *this_pid_s, struct token_iter *token_iter0) {
    char *dir = parse_optional_name(token_iter0);
    bool is_bg = parse_bg(token_iter0);
    if (token_iter_peek(token_iter0).type != TOKEN_TYPE_EOF) {
            if (is_bg) {
                fputs("There should be no tokens after `" TOKEN_BG "`.\n", stderr);
            } else {
                fputs("Command `cd` should have at most one argument"
                    " Please try again.\n",
                    stderr);
            }
    } else {
        if (dir == NULL) {
            /*handle_cd_chdir.... home? yes.*/
            handle_cd_chdir(getenv("HOME"));
        } else {
            char *dir_subs = expand_var(dir, this_pid_s);
            if (dir_subs == NULL) {
                fputs("internal error: handle_cd expand_var\n", stderr);
            } else {
                handle_cd_chdir(dir_subs);
                free(dir_subs);
            }
        }
    }
}



void print_term_signal(int status) {
    printf("terminated by signal %d", status);
}

void print_if_term_signal(int status) {
    if (WIFSIGNALED(status)) {
        print_term_signal(WTERMSIG(status));
        fputs("\n", stdout);
        fflush(stdout);
    }
}

void print_status(int status) {
    if (WIFEXITED(status)) {
        printf("exit value %d", WEXITSTATUS(status)); /*printing exit status*/
    } else if (WIFSIGNALED(status)) {
        print_term_signal(WTERMSIG(status));
    }
}



/**
 * This is meant to parse and execute the command `CMD_STATUS`.
 * Sources Used: https://www.mkssoftware.com/docs/man1/csh.1.asp
 * https://stackoverflow.com/questions/16587690/determine-command-status-in-c-shell
 * 
 */
void handle_status(int status, struct token_iter *token_iter0) {
    bool is_bg = parse_bg(token_iter0);
    if (token_iter_peek(token_iter0).type != TOKEN_TYPE_EOF) {
        if (is_bg) {
            fputs("There should be no tokens after `" TOKEN_BG "`.\n", stderr);
        } else {
            fputs("Command `exit` should have no arguments"
                " or stdin or stdout redirection.\n",
                stderr);
        }
        return;
    }
    print_status(status);
    fputs("\n", stdout);
    fflush(stdout);
}



/****************************************************************
 * A list of pid_t's of background processes.
 * Sources Used: https://www.youtube.com/watch?v=7ud2iqu9szk
 * https://www.unix.com/programming/45993-background-processes-dummy-shell.html
 * http://www.cs.fsu.edu/~cop4610t/lectures/project1/background_processes/background_processes.pdf
 * 
 */

#define MAX_BG_PROCESS_N 1024 /*define max*/

struct bg_processes { /*background*/
    size_t n;
    pid_t a[MAX_BG_PROCESS_N]; /*use defined max*/
};

void bg_processes_init(struct bg_processes *bg_processes0) {
    bg_processes0->n = 0;
}

/**
 * Whether there is a space for one element in bg_processes0.
 */
bool bg_processes_has_space(struct bg_processes *bg_processes0) {
    return bg_processes0->n != MAX_BG_PROCESS_N; /*use our max again*/
}

bool bg_processes_is_empty(struct bg_processes *bg_processes0) {
    return bg_processes0->n == 0;
}

bool bg_processes_insert(struct bg_processes *bg_processes0, pid_t pid) {
    if (bg_processes_has_space(bg_processes0)) {
        bg_processes0->a[bg_processes0->n] = pid;
        bg_processes0->n++;
        return true;
    }
    return false;
}

bool bg_processes_delete(struct bg_processes *bg_processes0, pid_t pid) {
    for (size_t i = bg_processes0->n; i-- != 0;) {
        if (bg_processes0->a[i] == pid) {
            bg_processes0->a[i] = bg_processes0->a[bg_processes0->n - 1];
            bg_processes0->n--;
            return true;
        }
    }
    return false;
}



/**
 * Collects and prints statuses of terminated child processes. It doesn't block.
 * Removes terminated child processes from bg_processes0.
 * Sources Used: https://www.geeksforgeeks.org/exit-status-child-process-linux/
 * https://stackoverflow.com/questions/27306764/capturing-exit-status-code-of-child-process
 * https://stackoverflow.com/questions/8199815/how-to-wait-for-all-child-processes-to-terminate-and-get-each-exit-status
 * https://cs.wellesley.edu/~cs240/f21/assignments/shell/
 */
void try_wait_child(struct bg_processes *bg_processes0) {
    int status;
    while (true) {
        pid_t child = waitpid(-1, &status, WNOHANG);
        if (child == -1) {
            if (errno == ECHILD) break;
            perror("try_wait_child");
            break;
        } else if (child != 0) {
            if (!bg_processes_delete(bg_processes0, child)) {
                fputs("unexpected ", stdout);
            }
            printf("background pid %" PRId32 " is done: ", (int32_t)child); /* print pid and child*/
            print_status(status); /*then status*/
            fputs("\n", stdout);
            fflush(stdout);
        } else break;
    }
}

/*bool block_sigint(void) { //note to self -- not yet, revisit and reconfigure later
    sigset_t a;
    if (sigprocmask(SIG_BLOCK, &a, NULL)) 
        return false  ?? yes? later
}*/

/**
 * Kills bg_processes0 and waits until they are terminated.
 * Sources Used: https://stackoverflow.com/questions/72715496/how-to-kill-all-background-processes-in-a-shell-with-controlc
 * https://stackoverflow.com/questions/24510348/kill-a-background-process-in-linux-using-a-c-program
 * https://www.baeldung.com/linux/kill-background-process
 */
void handle_exit_kill(struct bg_processes *bg_processes0) {
    for (size_t i = bg_processes0->n; i-- != 0;) {
        kill(bg_processes0->a[i], SIGKILL);
    }
    while (true) {
        try_wait_child(bg_processes0);
        if (bg_processes_is_empty(bg_processes0)) break;
        fputs("Waiting for background child processes...\n", stdout);
        fflush(stdout);
        sleep(1);
    }
}

/**
 * Parses and executes command `CMD_EXIT`.
 * Sources Used: https://stackoverflow.com/questions/4864670/how-to-exit-a-cmd-file-and-the-shell-at-the-same-time
 * https://stackoverflow.com/questions/51158574/c-shell-script-doesnt-exit
 */
bool
handle_exit(struct bg_processes *bg_processes0,
        struct token_iter *token_iter0) {
    bool is_bg = parse_bg(token_iter0);
    if (token_iter_peek(token_iter0).type != TOKEN_TYPE_EOF) {
        if (is_bg) {
            fputs("There should be no tokens after `" TOKEN_BG "`.\n", stderr);
        } else {
            fputs("Command exit should have no arguments"
                " Try again.\n",
                stderr);
        }
        return false;
    }
    handle_exit_kill(bg_processes0);
    return true;
}

bool block_sigint(void) {
    sigset_t a;
    sigemptyset(&a);
    sigaddset(&a, SIGINT);
    if (sigprocmask(SIG_BLOCK, &a, NULL)) {
        perror("block_sigint");
        return false;
    }
    return true;
}


        /** sigemptyset(&a);
    sigaddset(&a, SIGTSTP);*/
bool block_sigtstp(void) {
    sigset_t a;
    sigemptyset(&a);
    sigaddset(&a, SIGTSTP);
    if (sigprocmask(SIG_BLOCK, &a, NULL)) {
        perror("block_sigtstp");
        return false;
    }
    return true;
}

/**
 * `SIGINT` handler. Terminates this process.
 */
void handle_sigint(int signo) {
    /* Installs the default handler for SIGINT SIG_DFL
    and raises SIGINT again. This way, the parent process will see
    that this process is terminated by SIGINT,
    not just terminated normally with an exit status. 
    Sources Used: https://www.csl.mtu.edu/cs4411.ck/www/NOTES/signal/install.html
    https://stackoverflow.com/questions/33765810/parent-shell-not-getting-sigint-when-child-has-a-handler
    https://pubs.opengroup.org/onlinepubs/007908799/xsh/sigemptyset.html
    */

    struct sigaction sigaction_args;
    /*sigemptyset(sigaction_args) //revisit*/
    sigemptyset(&sigaction_args.sa_mask);
    sigaction_args.sa_flags = 0;
    sigaction_args.sa_handler = SIG_DFL;
    sigaction(signo, &sigaction_args, NULL);

    raise(signo);
}

/**
 * Sets handle_sigin as a SIGINT handler and unblocks SIGINT.
 * Sources Used:: https://www.gnu.org/software/libc/manual/html_node/Signals-in-Handler.html
 * https://stackoverflow.com/questions/66553769/blocking-sigint-within-an-sa-handler-in-c
 * https://stackoverflow.com/questions/47059627/blocking-and-unblocking-sigint-and-sigquit
 * https://unix.stackexchange.com/questions/543198/why-below-code-is-not-able-to-unblock-sigint-signal
 */
bool set_sigint_handler(void) {
    struct sigaction sigaction_args;
    sigemptyset(&sigaction_args.sa_mask);
    /*sigaction_args
    sigaction_args = 0*/
    sigaction_args.sa_flags = 0;
    sigaction_args.sa_handler = handle_sigint;
    if (sigaction(SIGINT, &sigaction_args, NULL) != 0) {
        perror("set_sigint_handler handler");
        return false;
    }

    sigset_t a;
    sigemptyset(&a);
    sigaddset(&a, SIGINT);
    if (sigprocmask(SIG_UNBLOCK, &a, NULL)) {
        perror("set_sigint_handler unblock");
        return false;
    }

    return true;
}



/****************************************************************
 * Child process.
 */

/**
 * Switches to an executable with arguments args0,
 * setting stdin and stdout redirection and a result.
 * If fd_in is -1, doesn't redirect STDIN_FILENO.
 * If fd_out is -1, doesn't redirect STDOUT_FILENO.
 * Sources Used: https://stackoverflow.com/questions/68962949/need-help-for-child-processes-in-c
 * https://www.educative.io/answers/how-to-do-input-output-redirection-in-linux
 * https://unix.stackexchange.com/questions/156114/what-are-some-practical-uses-of-stdin-redirection
 * https://fsl.fmrib.ox.ac.uk/fslcourse/unix_intro/io.html
 * https://linuxcommand.org/lc3_lts0070.php
 * 
 */
int child_process_exe(char **args0, int fd_in, int fd_out) {
    if (fd_in != -1) {
        if (dup2(fd_in, STDIN_FILENO) == -1) { /*doesnt redirect*/
            perror("dup2 in");
            return EXIT_FAILURE;
        }
        close(fd_in);
    }
    if (fd_out != -1) {
        if (dup2(fd_out, STDOUT_FILENO) == -1) { /*doesnt redirect*/
            perror("dup2 out");
            return EXIT_FAILURE;
        }
        close(fd_out);
    }
    execvp(args0[0], args0);
    /*Switching to the executable failed.*/
    perror("executing an external command");
    return EXIT_FAILURE;
}

/**
 * Switches to an executable with arguments args0,
 * setting stdin and stdout redirection.
 * If fd_in is -1, doesn't redirect STDIN_FILENO.
 * If cmd_out is NULL, doesn't redirect STDOUT_FILENO.
 * Sources Used: https://stackoverflow.com/questions/68962949/need-help-for-child-processes-in-c
 * https://www.educative.io/answers/how-to-do-input-output-redirection-in-linux
 * https://unix.stackexchange.com/questions/156114/what-are-some-practical-uses-of-stdin-redirection
 * https://fsl.fmrib.ox.ac.uk/fslcourse/unix_intro/io.html
 * https://linuxcommand.org/lc3_lts0070.php
 */
int child_process_out(char **args0, int fd_in, char *cmd_out) {
    if (cmd_out == NULL) {
        return child_process_exe(args0, fd_in, -1);
    } else {
        int fd_out = open(cmd_out, O_CREAT|O_WRONLY|O_TRUNC, 0755);
        if (fd_out == -1) {
            perror("opening a file for `stdout` redirection");
            return EXIT_FAILURE;
        } else {
            int r = child_process_exe(args0, fd_in, fd_out);
            return r;
        }
    }
}

/**
 * Switches to an executable with arguments args0,
 * setting stdin and stdout redirection.
 *
 * However, the meaning of cmd_in and cmd_out is slightly different.
 * They are intended for the function open. For example,
 * if the stdin redirection argument was left out in the command line,
 * cmd_in here should be "/dev/null", not NULL.
 * If cmd_in is NULL, doesn't redirect STDIN_FILENO.
 * If cmd_out is NULL, doesn't redirect STDOUT_FILENO.
 * Sources Used: https://ss64.com/nt/cmd.html
 * https://en.wikibooks.org/wiki/C_Shell_Scripting/Parameters
 */
int
child_process_in(struct args *args0, char *cmd_in, char *cmd_out, bool is_bg) {
    int r;
    if (cmd_in == NULL) {
        /*r = child_process_out(args, -1, cmd_out);*/
        r = child_process_out(args0->a, -1, cmd_out);
    } else {
        int fd_in = open(cmd_in, O_RDONLY);
        /*if (cmd_in == -1) { //wrong   */
        if (fd_in == -1) {
            perror("opening a file for `stdin` redirection");
            r = EXIT_FAILURE;
        } else {
            r = child_process_out(args0->a, fd_in, cmd_out);
        }
    }
    return r;
}

/**
 * The file path which a child process should open depending
 * on the file path in a redirection argument
 * and whether this process is background or not.
 * Sources Used: https://unix.stackexchange.com/questions/398672/setting-paths-for-interactive-c-shell
 * https://stackoverflow.com/questions/51942312/get-script-path-when-executing-it-in-c-shell
 * https://unix.stackexchange.com/questions/511954/how-to-reference-a-child-directory-that-is-part-of-cwds-path
 */
char *redirection_path_for_open(char *path, bool is_bg) {
    return is_bg && path == NULL ? "/dev/null" : path;
}

/**
 * Switches to an executable with arguments args0,
 * setting stdin and stdout redirection.
 * Returns the exit status of this process
 * in case switching to the executable failed.
 */
int
child_process_for_open(struct args *args0,
        char *cmd_in, char *cmd_out,
        bool is_bg) {
            /*cmd_in, cmd_out*/
    return child_process_in(args0,
        redirection_path_for_open(cmd_in, is_bg), /*path*/
        redirection_path_for_open(cmd_out, is_bg), /*path*/
        is_bg);
}

/**
 * Switches to an executable with arguments args0, setting signal handlers
 * and stdin and stdout redirection.
 * In line with the convention, the first argument in args0
 * is the path of the executable.
 * cmd_in is the file path where stdin should be redirected to.
 * It's taken from the redirection argument. It might be NULL.
 * Then, cmd_out is the file path where stdout should be redirected to.
 * It's taken from the redirection argument. Again, it might be NULL.
 * is_bg tells whether this process is background.
 * Sources Used: https://unix.stackexchange.com/questions/398672/setting-paths-for-interactive-c-shell
 * https://stackoverflow.com/questions/51942312/get-script-path-when-executing-it-in-c-shell
 * https://unix.stackexchange.com/questions/511954/how-to-reference-a-child-directory-that-is-part-of-cwds-path
 */
void
child_process(struct args *args0, char *cmd_in, char *cmd_out, bool is_bg) {
    int r;
    /*Child processes should ignore Ctrl-Z. */
    if (!block_sigtstp()) r = EXIT_FAILURE;
    else {
        if (is_bg) {
            /*r = child_process_in(args0, is_bg) //wrong, forgot in out*/
            r = child_process_in(args0, cmd_in, cmd_out, is_bg);
        } else {
            /* Non-background child processes should terminate on Ctrl-C.*/
            if (!set_sigint_handler()) r = EXIT_FAILURE;
            else {
                r = child_process_for_open(args0, cmd_in, cmd_out, is_bg);
            }
        }
    }
    free(cmd_in);
    free(cmd_out);
    args_destroy(args0);
    exit(r);
}

/**
 * This is whether the shell is in the foreground-only mode.
 * In this mode, `TOKEN_BG` in the command is ignored.
 * It's global because it's accessed from signal handler handle_sigtstp.
 * Sources Used: https://www.gnu.org/software/libc/manual/html_node/Foreground-and-Background.html
 * https://stackoverflow.com/questions/33808921/c-shell-signal-caught-by-parent-still-goes-to-child-process
 * https://cs.wellesley.edu/~cs240/f15/assignments/shell/shell.html
 * https://teaching.healthtech.dtu.dk/unix/index.php/Processes%3B_foreground_and_background,_ps,_top,_kill,_screen,_nohup_and_daemons
 */
bool is_fg_only_global = false;



struct exe_external_r {
    /*whether a child process was started */
    bool is_started;

    /* whether a child process was terminated */
    bool is_terminated;

    union {
        /**
         * The termination status of a child process as returned by wait.
         * Should be used only if is_terminated is true.
         * Otherwise, it should not be used, we will handle that next.
         */
        int status;

        /**
         * The PID of a child process.
         * Should be used only if is_terminated is false.
         */
        pid_t pid;
    } a;
};

struct exe_external_r
exe_external(struct args *args0, char *cmd_in, char *cmd_out, bool is_bg) {
    struct exe_external_r r = {.is_started = false};

    /* Inserts NULL into args0 since execvp requires
    that the argument list is NULL-terminated. */
    if (!args_insert(args0, NULL)) {
        fputs("Too many arguments in the command.\n", stderr);
        return r;
    }

    /* Creates a child process. */
    /*https://stackoverflow.com/questions/50385398/creating-child-process-in-c-linux*/

    pid_t child = fork();
    if (child == -1) {
        perror("fork");
    } else if (child == 0) {
        child_process(args0, cmd_in, cmd_out, is_bg);
    } else {
        /* parent */
        r.is_started = true;
        if (is_bg) {
            printf("background pid is %" PRId32 "\n", (int32_t)child); /*print pid*/
            fflush(stdout);
            /*r.is_terminated
            //r.pid = child */
            r.is_terminated = false;
            r.a.pid = child;
        } else {
            /* Since the child process isn't background,
            wait for its termination. */
            if (waitpid(child, &r.a.status, 0) == -1) {
                perror("waitpid");
                r.is_terminated = false;
                r.a.pid = child;
            } else {
                print_if_term_signal(r.a.status);
                r.is_terminated = true;
            }
        }
    }

    return r;
}

/**
 * Executes external command args0.
 * cmd_in is the file path where stdin should be redirected to.
 * It's taken from the redirection argument. May be NULL.
 * cmd_out is the file path where stdout should be redirected to.
 * It's taken from the redirection argument. May be `NULL`.
 * is_bg is whether there is TOKEN_BG in the command.
 * Sources Used: https://unix.stackexchange.com/questions/398672/setting-paths-for-interactive-c-shell
 * https://stackoverflow.com/questions/51942312/get-script-path-when-executing-it-in-c-shell
 * https://unix.stackexchange.com/questions/511954/how-to-reference-a-child-directory-that-is-part-of-cwds-path
 */
struct exe_external_r
exe_external_fg_only(struct args *args0,
        char *cmd_in, char *cmd_out,
        bool is_bg) {
    /* Blocks SIGTSTP while reading is_fg_only_global.
    This is required because handle_sigtstp also accesses is_fg_only_global.
    */
    struct exe_external_r r = {.is_started = false};
    /*sigemptyset(&sigset);
    sigaddset(&sigset); wrong*/
    sigset_t old_sigset, sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTSTP);
    if (sigprocmask(SIG_BLOCK, &sigset, &old_sigset)) {
        perror("handle_external_bg sigprocmask block");
    } else {
        bool is_fg_only = is_fg_only_global;
        /* Goes back to the previous signal mask. */
        if (sigprocmask(SIG_SETMASK, &old_sigset, NULL)) {
            perror("handle_external_bg sigprocmask revert");
        } else {
            r = exe_external(args0, cmd_in, cmd_out, is_bg && !is_fg_only);
        }
    }
    return r;
}

/**
 * args0 should be non-empty.
 */
struct exe_external_r
handle_external_bg(struct args *args0,
        char *cmd_in, char *cmd_out,
        struct token_iter *token_iter0) {
    struct exe_external_r r = {.is_started = false};

    /* Parses TOKEN_BG. */
    bool is_bg = parse_bg(token_iter0);
    if (token_iter_peek(token_iter0).type
        != TOKEN_TYPE_EOF) {
        fputs("There should be no tokens after `" TOKEN_BG "`"
            " or stdin or stdout redirection.\n",
            stderr);
    } else {
        r = exe_external_fg_only(args0, cmd_in, cmd_out, is_bg);
    }

    return r;
}

struct redirection_arg {
    /*bool*/
    bool is_success;
    char *s;
};

/**struct args *args0,
        char *cmd_in,
        struct token_iter *token_iter0) {
    struct exe_external_r r = {.is_started = false};*/

enum redirection_type {REDIRECTION_TYPE_IN, REDIRECTION_TYPE_OUT};

/**
 * Parses an optional stdin or stdout redirection arguments
 * consuming the token stream token_iter0.
 * If is_success of the result is true, s of the result points
 * to the file path in the redirection argument.
 * s is inside the string that token_iter0 refers to.
 * Sources Used: https://unix.stackexchange.com/questions/398672/setting-paths-for-interactive-c-shell
 * https://stackoverflow.com/questions/51942312/get-script-path-when-executing-it-in-c-shell
 * https://unix.stackexchange.com/questions/511954/how-to-reference-a-child-directory-that-is-part-of-cwds-path
 */
struct redirection_arg
parse_redirection(struct token_iter *token_iter0,
        enum redirection_type redirection_type0) {
    struct redirection_arg r;
    enum token_type token_type0 = token_iter_peek(token_iter0).type;
    if (token_type0
        != (redirection_type0 == REDIRECTION_TYPE_IN
            ? TOKEN_TYPE_IN : TOKEN_TYPE_OUT)) {
        /* not a redirection argument*/
        r.is_success = true;
        r.s = NULL;
    } else {
        /* redirection argument*/
        token_iter_next(token_iter0);
        struct token token1 = token_iter_peek(token_iter0);
        if (token1.type != TOKEN_TYPE_NAME) {
            /*no file path after TOKEN_IN or TOKEN_OUT
            == True wrong*/
            r.is_success = false;
        } else {
            token_iter_next(token_iter0);
            r.is_success = true;
            r.s = token1.s;
        }
    }
    return r;
}

struct exe_external_r
handle_external_out(const char *this_pid_s,
        struct args *args0,
        char *cmd_in,
        struct token_iter *token_iter0) {
    struct exe_external_r r = {.is_started = false};

    /*Parses the stdout redirection argument.*/
    struct redirection_arg cmd_out = parse_redirection(
        token_iter0, REDIRECTION_TYPE_OUT);
    if (!cmd_out.is_success) {
        fputs("Invalid stdout redirection.\n", stderr);
    } else {
        if (cmd_out.s == NULL) {
            r = handle_external_bg(args0, cmd_in, NULL, token_iter0);
        } else {
            char *cmd_out_subs = expand_var(cmd_out.s, this_pid_s);
            if (cmd_out_subs == NULL) {
                fputs("internal error: handle_external expand_var out\n",
                    stderr);
            } else {
                r = handle_external_bg(args0, cmd_in, cmd_out_subs,
                    token_iter0);
                free(cmd_out_subs);
            }
        }
    }

    return r;
}


struct exe_external_r
handle_external_in(const char *this_pid_s,
        struct args *args0,
        struct token_iter *token_iter0) {
    struct exe_external_r r = {.is_started = false};

    /*Parses the stdin redirection argument.*/
    struct redirection_arg cmd_in = parse_redirection(
        token_iter0, REDIRECTION_TYPE_IN);
    if (!cmd_in.is_success) {
        fputs("Invalid stdin redirection.\n", stderr);
    } else {
        if (cmd_in.s == NULL) {
            r = handle_external_out(this_pid_s, args0, NULL, token_iter0);
        } else {
            char *cmd_in_subs = expand_var(cmd_in.s, this_pid_s);
            if (cmd_in_subs == NULL) {
                fputs("internal error: handle_external expand_var"
                    " in\n",
                    stderr);
            } else {
                r = handle_external_out(this_pid_s, args0, cmd_in_subs,
                    token_iter0);
                free(cmd_in_subs);
            }
        }
    }

    return r;
}

/**
 * Parses an external command and executes it in a child process.
 * token_subs is the first TOKEN_TYPE_NAME in the command line
 * already consumed from token_iter0.
 * Sources Used: https://unix.stackexchange.com/questions/398672/setting-paths-for-interactive-c-shell
 * https://stackoverflow.com/questions/51942312/get-script-path-when-executing-it-in-c-shell
 * https://unix.stackexchange.com/questions/511954/how-to-reference-a-child-directory-that-is-part-of-cwds-path
 */
struct exe_external_r
handle_external(const char *this_pid_s,
        char *token_subs,
        struct token_iter *token_iter0) {
    struct args args0;
    args_init(&args0);
    struct exe_external_r r = {.is_started = false};
    /* Moves the first TOKEN_TYPE_NAME from token_iter0 to args0.*/
    if (!args_insert(&args0, token_subs)) {
        fputs("Too many arguments in the command.\n", stderr);
        free(token_subs);
    } else {
        /* Moves the remaining TOKEN_TYPE_NAME from token_iter0 to args0.
        */
        while (true) {
            /*if (token_iter_peek(token_iter0).type == TOKEN_TYPE_EOF) {
                    r = exe_external_fg_only(&args0, NULL, NULL, true);
                    break;*/
            struct token token1 = token_iter_peek(token_iter0);
            if (token1.type == TOKEN_TYPE_BG) {
                token_iter_next(token_iter0);
                if (token_iter_peek(token_iter0).type == TOKEN_TYPE_EOF) {
                    r = exe_external_fg_only(&args0, NULL, NULL, true);
                    break;
                } else {
                    /* TOKEN_BG isn't at the end, so treat it
                    as a usual command argument. */
                    char *token1_subs = strdup(TOKEN_BG);
                    /*char *token1_subs = expand_var(token1.s, this_pid_s); move...*/
                    if (!args_insert(&args0, token1_subs)) {
                        fputs("Too many arguments in the command.\n", stderr);
                        free(token1_subs);
                        break;
                    }
                }
            } else if (token1.type == TOKEN_TYPE_NAME) {
                token_iter_next(token_iter0);
                char *token1_subs = expand_var(token1.s, this_pid_s);
                if (token1_subs == NULL) {
                    fputs("internal error: handle_external expand_var middle\n",
                        stderr);
                    break;
                }
                if (!args_insert(&args0, token1_subs)) {
                    fputs("Too many arguments in the command.\n", stderr);
                    free(token1_subs);
                    break;
                }
            } else {
                r = handle_external_in(this_pid_s, &args0, token_iter0);
                break;
            }
        }
    }
    args_destroy(&args0);
    return r;
}



/**
 * Parses and executes command cmd. cmd should be a whole command line.
 * this_pid_s is the PID of this shell.
 * last_status is the termination status of the last foreground child process
 * as returned by wait.
 * Returns whether cmd is CMD_EXIT.
 * Sources Used: https://stackoverflow.com/questions/50504069/c-shell-executing-commands-from-script
 * https://stackoverflow.com/questions/19209141/how-do-i-execute-a-shell-built-in-command-with-a-c-function
 * https://ss64.com/nt/exit.html
 * https://stackoverflow.com/questions/53760363/exit-from-command-prompt-after-running-r-script
 * https://superuser.com/questions/1137844/exit-the-linux-shell-back-to-command-prompt
 */
bool
handle_cmd(const char *this_pid_s,
        int *last_status,
        struct bg_processes *bg_processes0,
        char *cmd) {
    /* Do nothing because cmd is empty. */
    if (cmd[0] == '\0') return false;

    /*char *token_subs = expand_var(token0.s, this_pid_s);
    if (token_subs == NULL) ...wrong..down more
    }*/

    /* Do nothing because cmd is a comment.*/
    if (cmd[0] == '#') return false;

    struct token_iter token_iter0;
    token_iter_init(&token_iter0, cmd);

    struct token token0 = token_iter_peek(&token_iter0);

    /*Do nothing because cmd is empty.*/
    if (token0.type == TOKEN_TYPE_EOF) return false;

    if (token0.type != TOKEN_TYPE_NAME) {
        fputs("A command should start with a name.\n", stderr);
        return false;
    }

    char *token_subs = expand_var(token0.s, this_pid_s);
    if (token_subs == NULL) {
        fputs("internal error: handle_cmd expand_var first\n", stderr);
        return false;
    }

    bool r = false;
    /*free(token_subs);
        token_iter_next(&token_iter0);*/
    if (str_eq(token_subs, CMD_EXIT)) {
        free(token_subs);
        token_iter_next(&token_iter0);
        r = handle_exit(bg_processes0, &token_iter0);
    } else if (str_eq(token_subs, CMD_CD)) {
        free(token_subs);
        token_iter_next(&token_iter0);
        handle_cd(this_pid_s, &token_iter0);
    } else if (str_eq(token_subs, CMD_STATUS)) {
        token_iter_next(&token_iter0);
        handle_status(*last_status, &token_iter0);
    } else {
        /* Parses an external command and executes it in a child process.
        Writes the termination status of the child process to last_status
        if the child process has terminated.
        Adds the child process to bg_processes0 if the child process
        hasn't terminated. */
        token_iter_next(&token_iter0);
        if (!bg_processes_has_space(bg_processes0)) {
            free(token_subs);
            fputs("Too many background processes.\n", stderr);
        } else {
            /*this_pid_s*/
            struct exe_external_r exe_external_r0 = handle_external(
                this_pid_s, token_subs, &token_iter0);
            if (exe_external_r0.is_started) {
                if (exe_external_r0.is_terminated) {
                    *last_status = exe_external_r0.a.status;
                } else {
                    bg_processes_insert(bg_processes0, exe_external_r0.a.pid);
                }
            }
        }
    }
    return r;
}

#define PROMPT ": "

void print_prompt(void) {
    fputs(PROMPT, stdout);
    fflush(stdout);
}

/**
 * Writes buffer to fd. size is the size of buffer.
 * This function is async-safe, so it may be used in signal handlers.
 * Sources Used: https://man7.org/linux/man-pages/man7/signal-safety.7.html
 * https://unix.stackexchange.com/questions/230079/how-to-append-data-to-buffer-in-shell-script
 * https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/
 */
bool write_all(int fd, const void *buffer, size_t size) {
    const char *buffer1 = buffer;
    while (size != 0) {
        ssize_t size1 = write(fd, buffer1, size);
        /*if
        if (size1 <0) {}*/
        if (size1 < 0) return false;
        size -= size1;
        buffer1 += size1;
    }
    return true;
}



#define FG_ONLY_ON "\nEntering foreground-only mode (" TOKEN_BG " is now ignored)\n" PROMPT
#define FG_ONLY_OFF "\nExiting foreground-only mode\n" PROMPT

/**
 * Toggles is_fg_only_global. Prints an informative message that we pre-defined.
 */
void handle_sigtstp(int signo) {
    is_fg_only_global = !is_fg_only_global;
    const char *const s = is_fg_only_global ? FG_ONLY_ON : FG_ONLY_OFF; /*foreground only on and off*/
    const size_t s_size = (is_fg_only_global
        ? sizeof(FG_ONLY_ON) : sizeof(FG_ONLY_OFF))
        - sizeof(char);
    write_all(STDOUT_FILENO, s, s_size);
}



/**
 * Sets handle_sigtstp as a SIGTSTP handler and unblocks SIGTSTP.
 * Sources Used: https://stackoverflow.com/questions/40098170/handling-sigtstp-signals-in-c
 * https://man7.org/tlpi/code/online/dist/pgsjc/handling_SIGTSTP.c.html
 * https://github.com/Arkham/c_examples/blob/master/apue/signals/sigtstp.c
 * https://www.yendor.com/programming/unix/apue/signals/sigtstp.c
 * https://www.youtube.com/watch?v=3MZjaZxZYrE
 */
bool set_sigtstp_handler(void) {
    struct sigaction sigaction_args;
    sigemptyset(&sigaction_args.sa_mask);
    /*sig*/
    sigaction_args.sa_flags = SA_RESTART;
    sigaction_args.sa_handler = handle_sigtstp;
    if (sigaction(SIGTSTP, &sigaction_args, NULL) != 0) {
        perror("set_sigtstp_handler handler");
        return false;
    }

    sigset_t a;
    sigemptyset(&a);
    sigaddset(&a, SIGTSTP);
    if (sigprocmask(SIG_UNBLOCK, &a, NULL) != 0) {
        perror("set_sigtstp_handler unblock");
        return false;
    }

    return true;
}

/*while(true) { // note to self -- put down further, reconfigure, needs to be at end
        try_wait_child(&bg_processes0);
        print_prompt();
        if (!read_line(CMD_BUFFER_SIZE, cmd)) {
            handle_exit_kill(&bg_processes0);
            break;*/


/** the maximum length of a command line */
const size_t MAX_CMD_LEN = 2048;

/**
 * command line buffer size: one additional char for '\n',
 * one additional char` for '\0'
 */
const size_t CMD_BUFFER_SIZE = (MAX_CMD_LEN + 2) * sizeof(char);

int main(void) {
    /* The shell should ignore Ctrl-C. */
    if (!block_sigint()) return EXIT_FAILURE;

    /* The shell should toggle the foreground-only mode on Ctrl-Z. */
    if (!set_sigtstp_handler()) return EXIT_FAILURE;

    /* The PID of this shell. We assume that it's int32_t.
    It's specified that it's signed, but its size isn't specified. */
    const size_t PID_LEN = /* `len(str(- (2 ** (32 - 1))))` */ 11;
    char this_pid_s[PID_LEN + 1];
    if (snprintf(this_pid_s, PID_LEN + 1, "%" PRId32, (int32_t)getpid()) < 0) {
        fputs("Can't obtain this process PID.\n", stderr);
        return EXIT_FAILURE;
    }

    /* the termination status of the last foreground child process
    as returned by wait */
    int last_status = 0;

    /* PIDs of background processes */
    struct bg_processes bg_processes0;
    bg_processes_init(&bg_processes0);

    char cmd[CMD_BUFFER_SIZE];

    /*read-execute loop*/ 
    while(true) {
        try_wait_child(&bg_processes0);
        print_prompt();
        if (!read_line(CMD_BUFFER_SIZE, cmd)) {
            /* Exits if stdin was closed. */
            fputs("\n", stdout);
            fflush(stdout);
            handle_exit_kill(&bg_processes0);
            break;
        }
        if (handle_cmd(this_pid_s, &last_status, &bg_processes0, cmd)) {
            /* Exits if cmd is CMD_EXIT. */
            break;
        }
    }

    return EXIT_SUCCESS;
}
