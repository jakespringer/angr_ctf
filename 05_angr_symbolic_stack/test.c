
typedef struct {
  int a, b, c, d, e, f, g;
  float z, x, y, l;
  char k[12];
} mystruct;

mystruct func() {
  mystruct str;
  return str;
}

int main(int argc, char* argv[]) {
  mystruct str = func();
  str.a = 4;
  return 0;
}
