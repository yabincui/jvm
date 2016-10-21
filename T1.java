public class T1 {

  float fv = 3.72f;
  double dv = 6.375;
  int iv = 65536;
  long lv = (1L << 63);

  public int a;

  void func1() {
    System.out.printf("hello, world!\n");
  }

  public static void main() {
    T1 obj = new T1();
    obj.func1();
  }
}
