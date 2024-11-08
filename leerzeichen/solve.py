def is_int(op):
    return 0x2000 <= op <= 0x200a


with open("chal.lrz", "rb") as f:
    debug = False
    out = []


    def exec(ops, st):
        if debug:
            print("EXEC", list(map(hex, ops)))

        i = 0
        while i < len(ops):
            op = ops[i]
            if debug:
                print(i, [c if isinstance(c, int) else list(map(hex, c)) for c in st], hex(op))

            # integer
            if is_int(op):
                ints = []
                j = 0
                while i + j < len(ops) and is_int(ops[i + j]):
                    ints.append(ops[i + j])
                    j += 1
                if j > 3:
                    for _ in range(3, j):
                        ints.pop()

                n = op - 0x2000
                if len(ints) == 1 or (len(ints) == 3 and ints[1] - 0x2000 != 10):
                    st.append(n)
                    i += 1

                    if debug:
                        print("INSERT", n)
                elif len(ints) == 2:  # or (len(ints) == 3 and ints[1] - 0x2000 != 10):
                    m = ops[i + 1] - 0x2000
                    if n != 10 and m != 10:
                        st.append(n)
                        st.append(m)
                    elif n == 10:
                        st.append(10 + m)
                    elif m == 10:
                        st.append(10 * n)
                    else:
                        assert False
                    i += 2

                    if debug:
                        print("INSERT", n, m)
                elif len(ints) == 3:
                    m = ops[i + 1] - 0x2000
                    u = ops[i + 2] - 0x2000
                    # if m != 10:
                    #     print(i, n, m, u)
                    assert m == 10
                    st.append(10 * n + u)
                    i += 3

                    if debug:
                        print("INSERT", n, m, u)
                continue
            elif op == 0x0009:
                try:
                    print(chr(st[-1]), end="")
                    out.append(chr(st[-1]))
                    st.pop()
                except Exception:
                    print("A")
            elif op == 0x000a:
                st.append(st.pop() + st.pop())
            elif op == 0x000b:
                st.append(st.pop() - st.pop())
            elif op == 0x000c:
                st.append(st.pop() * st.pop())
            elif op == 0x000d:
                st.append(st.pop() // st.pop())
            elif op == 0x3164:
                st.append(max(st.pop(), st.pop()))
            elif op == 0x0020:
                st.pop()
            elif op == 0x00a0:
                st.append(st[-1])
            elif op == 0x202f:
                st[-1], st[-2] = st[-2], st[-1]
            elif op == 0x205f:
                st[-1], st[-2], st[-3] = st[-2], st[-3], st[-1]
            elif op == 0x3000:
                a, b, c = st.pop(), st.pop(), st.pop()
                if c == 0:
                    exec(a, st)
                else:
                    exec(b, st)
            elif op == 0x200b:
                p = []
                psum = 1
                i += 1
                while psum > 0:
                    if ops[i] == 0x200b:
                        psum += 1
                    elif ops[i] == 0x200c:
                        psum -= 1
                    p.append(ops[i])
                    i += 1
                st.append(p)
                continue
            elif op == 0x200c:
                pass
            elif op == 0x2060:
                if debug:
                    print("RETURN")
                return
            else:
                print(hex(op))
                assert False
            i += 1

        if debug:
            print("END EXEC")


    st = []
    ops = list(map(ord, f.read().decode("utf-8")))
    exec(ops, st)

    print()
    print("OUT HEX:", " ".join(map(hex, map(ord, out))))
    print("OUT:", "".join(out))
