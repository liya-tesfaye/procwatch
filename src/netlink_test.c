#include <stdio.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <string.h>

struct proc_event_msg {
    struct nlmsghdr nl_hdr;
    struct cn_msg cn_hdr;
    enum proc_cn_mcast_op op;
};

int main(void) {
    int netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

    if (netlink_socket == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_nl addr = {0};

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = CN_IDX_PROC;

    int bind_response = bind(netlink_socket, (struct sockaddr *)&addr, sizeof(addr));

    if (bind_response == -1){
        perror("bind");
        close(netlink_socket);
        return 1;
    }

    struct proc_event_msg msg = {0};
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    msg.nl_hdr.nlmsg_flags = 0;
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.cn_hdr.id.idx = CN_IDX_PROC;
    msg.cn_hdr.id.val = CN_VAL_PROC;
    msg.cn_hdr.len = sizeof(enum proc_cn_mcast_op);
    msg.op = PROC_CN_MCAST_LISTEN;

    struct sockaddr_nl kernel_addr = {0};
    kernel_addr.nl_family = AF_NETLINK;
    kernel_addr.nl_pid = 0;
    kernel_addr.nl_groups = CN_IDX_PROC;
    
    ssize_t bytes = sendto(
        netlink_socket,
        &msg,
        sizeof(msg),
        0,
        (struct sockaddr *)&kernel_addr,
        sizeof(kernel_addr)
    );
    printf("Sent %zd bytes\n", bytes);

    if (bytes == -1)
    {
        perror("send");
        close(netlink_socket);
        return 1;
    }
    printf("Subscribed. Waiting for events...\n");
    fflush(stdout);

    char buffer[4096];

    while (1)
    {
        ssize_t len = recv(
            netlink_socket,
            buffer,
            sizeof(buffer),
            0
        );

        if (len == -1)
        {
            perror("recv");
            break;
        }

        printf("Received %zd bytes\n", len);
    }

    close(netlink_socket);
    return 0;    
}