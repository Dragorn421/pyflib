int global = 421;

void test2(int);

void test()
{
    test2(global);
}

void test_other()
{
    global = 3;
}
