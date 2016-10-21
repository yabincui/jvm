public class Spin {
  public void spin() {
    int i;
    for (i = 0; i < 100; ++i) {
    }
  }

  public void spinDouble() {
    double d;
    for (d = 0; d < 100.0; ++d) {
    }
  }

  public double doubleLocals(double d1, double d2) {
    return d1 + d2;
  }

  public void spinShort() {
    short s;
    for (s = 0; s < 100; ++s) {
    }
  }

  int align2grain(int i, int grain) {
    return ((i + grain - 1) & ~(grain-1));
  }

  void useManyNumeric() {
    int i = 100;
    int j = 1000000;
    long l1 = 1;
    long l2 = 0xffffffff;
    double d = 2.2;
  }

  int lessThan100(double d) {
    if (d < 100.0) {
      return 1;
    } else {
      return -1;
    }
  }

  int greaterThan100(double d) {
    if (d > 100.0) {
      return 1;
    } else {
      return -1;
    }
  }

  int addTwo(int i, int j) {
    return i + j;
  }

  static int addTwoStatic(int i, int j) {
    return i + j;
  }

  int add12and13() {
    return addTwo(12, 13);
  }

  int add12and13Static() {
    return addTwoStatic(12, 13);
  }

  class Near {
    int it;
    int getItNear() {
      return getIt();
    }
    private int getIt() {
      return it;
    }
  }

  class Far extends Near {
    int getItFar() {
      return super.getItNear();
    }
  }

  Spin example() {
    Spin o = new Spin();
    return silly(o);
  }
  Spin silly(Spin o) {
    if (o != null) {
      return o;
    } else {
      return o;
    }
  }

  int i;
  void setIt(int value) {
    i = value;
  }
  int getIt() {
    return i;
  }

  void createBuffer() {
    int buffer[];
    int bufsz = 100;
    int value = 12;
    buffer = new int[bufsz];
    buffer[10] = value;
    value = buffer[11];
  }

  void createThreadArray() {
    Thread threads[];
    int count = 10;
    threads = new Thread[count];
    threads[0] = new Thread();
  }

  int[][][][] create3DArray() {
    int grid[][][][];
    grid = new int[10][5][6][];
    return grid;
  }

  int chooseNear(int i) {
    switch (i) {
      case 0: return 0;
      case 1: return 1;
      case 2: return 2;
      default: return -1;
    }
  }

  int chooseFar(int i) {
    switch (i) {
      case -100: return -1;
      case 0: return 0;
      case 100: return 1;
      default: return -1;
    }
  }

  private long index;
  public long nextIndex() {
    return index++;
  }

  class TestExc extends Throwable {}

  void cantBeZero(int i) throws TestExc {
    if (i == 0) {
      throw new TestExc();
    }
  }

  void catchOne() {
    try {
      cantBeZero(0);
    } catch (TestExc e) {
      handleExc(e);
    }
  }

  void handleExc(TestExc e) {
  }

  class TestExc2 extends Throwable {}

  void cantBeZero2(int i) throws TestExc2 {
    if (i == 0) {
      throw new TestExc2();
    }
  }
  void catchTwo() {
    try {
      cantBeZero(0);
      cantBeZero2(0);
    } catch (TestExc e) {
      handleExc(e);
    } catch (TestExc2 e) {
      handleExc2(e);
    }
  }

  void handleExc2(TestExc2 e) {
  }

  void nestedCatch() {
    try {
      try {
        cantBeZero(0);
        cantBeZero2(0);
      } catch (TestExc e) {
        handleExc(e);
      }
    } catch (TestExc2 e) {
      handleExc2(e);
    }
  }

  void tryFinally() throws TestExc {
    try {
      cantBeZero(0);
    } finally {
      handleExc(null);
    }
  }

  void onlyMe(TestExc e) {
    synchronized(e) {
      handleExc(e);
    }
  }
}
