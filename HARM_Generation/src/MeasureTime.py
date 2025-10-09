import time
def run_with_timing():
    """Run NetGen with comprehensive timing measurements."""
    
    print("Starting comprehensive timing measurement...")
    total_start = time.time()
    
    # Measure import time
    import_start = time.time()
    from NetGen import main
    import_end = time.time()
    import_time = import_end - import_start
    
    print(f"Import time (including LLM imports): {import_time:.3f} seconds")
    
    # Measure execution time
    execution_start = time.time()
    main()
    execution_end = time.time()
    execution_time = execution_end - execution_start
    
    total_end = time.time()
    total_time = total_end - total_start
    
    print(f"\n=== TIMING SUMMARY ===")
    print(f"Import time: {import_time:.3f} seconds")
    print(f"Execution time: {execution_time:.3f} seconds")
    print(f"Total time: {total_time:.3f} seconds")

# Entry point for script execution
run_with_timing()