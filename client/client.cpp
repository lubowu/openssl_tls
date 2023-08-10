#include "eth_access_task.h"

#include <thread>
#include <unistd.h>

void* eth_access_taskMain(void* params);

int main()
{
    std::thread task(eth_access_taskMain, nullptr);
    task.detach();
    EthAccessTask::Instance()->Start();

    while(1)
    {
        sleep(1);
    }

}