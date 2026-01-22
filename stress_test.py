import time
import math
import multiprocessing

def stress_cpu():
    print("Process started... (Press Ctrl+C to stop)")
    while True:
        # Intense math calculation to heat up the CPU
        [math.sqrt(i) for i in range(1000000)]

if __name__ == '__main__':
    # Launch 2 processes to max out your Dual-Core i5
    processes = []
    print(f"Starting Stress Test on {multiprocessing.cpu_count()} cores...")
    
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=stress_cpu)
        p.start()
        processes.append(p)

    try:
        # Run for 10 seconds then cleanup
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping stress test...")
        for p in processes:
            p.terminate()