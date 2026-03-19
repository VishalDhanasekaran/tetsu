## Traditional Linux Networking Stack (Slow Path):
```
            Incoming Network Packet
                        │
                        ▼
              ┌───────────────────┐
              │   Network Card    │
              │       (NIC)       │
              └───────────────────┘
                        │
                        │  Hardware Interrupt
                        ▼
                ┌───────────────┐
                │   NIC Driver  │
                │   (Kernel)    │
                └───────────────┘
                        │
                        │  DMA Copy
                        ▼
               ┌─────────────────────┐
               │  sk_buff Structure  │
               │  (Kernel Memory)    │
               └─────────────────────┘
                        │
                        ▼
        ┌────────────────────────────────┐
        │      Linux Network Stack       │
        │                                │
        │  Ethernet → IP → TCP Parsing   │
        │  Routing Table Lookup          │
        │  Firewall Rules (iptables)     │
        │  Netfilter Hooks               │
        └────────────────────────────────┘
                        │
                        │ Context Switch
                        ▼
              ┌─────────────────────┐
              │  User Space App     │
              │  HAProxy / Nginx    │
              └─────────────────────┘
                        │
                        │ Memory Copy
                        ▼
              ┌─────────────────────┐
              │ Application Logic   │
              │ Decide Backend      │
              └─────────────────────┘
                        │
                        │
                        ▼
         ┌─────────────────────────────┐
         │ Packet Sent Back To Kernel  │
         │ (another context switch)    │
         └─────────────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   NIC Driver      │
              └───────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │      NIC TX       │
              └───────────────────┘
                        │
                        ▼
                   Network


```

## eBPF / XDP Networking (Fast Path) 
```
                  Incoming Packet
                        │
                        ▼
              ┌───────────────────┐
              │   Network Card    │
              │       (NIC)       │
              └───────────────────┘
                        │
                        │ DMA → RAM
                        ▼
             ┌──────────────────────┐
             │ RX Ring Buffer       │
             │ (Driver Memory)      │
             └──────────────────────┘
                        │
                        │
                        ▼
          ┌───────────────────────────┐
          │      XDP HOOK (Driver)    │
          │  eBPF Program Executes    │
          │                           │
          │  Parse Ethernet/IP/TCP    │
          │  Lookup eBPF Map          │
          │  Select Backend Server    │
          └───────────────────────────┘
                        │
                        │
        ┌───────────────┼───────────────────┐
        │               │                   │
        ▼               ▼                   ▼
   XDP_PASS        XDP_DROP           XDP_REDIRECT
  (Kernel stack)   (Discard)         (Forward packet)
                                           │
                                           ▼
                               ┌───────────────────┐
                               │  NIC TX Queue     │
                               │  (Zero-Copy)      │
                               └───────────────────┘
                                           │
                                           ▼
                                       Network

```

## Where parellelism Happens

              NIC Hardware
            (Multiple RX Queues)

         Queue0 → CPU Core 0 → XDP
         Queue1 → CPU Core 1 → XDP
         Queue2 → CPU Core 2 → XDP
         Queue3 → CPU Core 3 → XDP

