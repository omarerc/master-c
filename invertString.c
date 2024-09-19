#include <stdio.h>
#include <string.h>

int main() {
  char line[1000];
  printf("Type a Sentence:\n");
  scanf("%[^\n]1000s", line);
  int l = strlen(line) - 1;
  int i = 0;
  while ((line[i] != '\0')) {
    printf("%c", line[l]);
    i++;
    l--;
  }
  printf("\n");
  return 0;
}