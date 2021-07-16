#include <stdio.h>

#define MAX_READABLE_SUFFIX 9

char *readable_number_suffix[MAX_READABLE_SUFFIX] = {
    (char *)"",
    (char *)"K",
    (char *)"M",
    (char *)"G",
    (char *)"T",
    (char *)"P",
    (char *)"E",
    (char *)"Z",
    (char *)"Y"
};

void get_readable_number_float(double power,
                               double input,
                               double *num_output,
                               char **str_output) {
    unsigned int index = 0;
    while ((input > power) && ((index + 1) < MAX_READABLE_SUFFIX)) {
    index++;
    input = input / power;
    }
    *num_output = input;
    *str_output = readable_number_suffix[index];

}
