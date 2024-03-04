public class Main {
    public static void main(String[] args) {
        System.out.println("PID: " + ProcessHandle.current().pid());

        // Infinite loop to call a1 method.
        while (true) {
            a1();
        }
    }

    public static void cpu() {
        // Loop 1001 times, similar to the Python script
        for (int i = 0; i < 1001; i++) {
            // Just a placeholder loop. Does nothing.
            System.out.println("WUT?");
        }
    }

    public static void c1() {
        cpu();
    }

    public static void b1() {
        c1();
    }

    public static void a1() {
        b1();
    }
}
