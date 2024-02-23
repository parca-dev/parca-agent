import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class Main {
    public static void main(String[] args) {
	System.out.println("PID: "+ ProcessHandle.current().pid());
	Runnable r = () -> {
	    while (true ) {
		recurse_and_spin(11);
	    }
	};
	int threads = Runtime.getRuntime().availableProcessors() / 2 + 1;
	ExecutorService executorService = Executors.newFixedThreadPool(threads);
	for (int i=0; i < threads; i++) {
	    executorService.submit(r);
	}
    }

    static void recurse_and_spin(int x) {
        if (x > 0) {
            recurse_and_spin(x - 1);
        } else {
            long pid = ProcessHandle.current().pid();
	    try {
		Path procDir = Paths.get("/proc", "" + pid);
		File[] files = procDir.toFile().listFiles();
		if (files.length == 0) {
		    System.out.println("WUT?");
		}
	    } catch(Exception e) {
		System.err.println(e);
	    }
        }
    }
}
