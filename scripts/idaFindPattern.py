"""
ida 脚本，一键搜索hook函数地址和生成唯一特征码（理论适配所有微信4.0+版本）
原理：https://bbs.kanxue.com/thread-284417-1.htm
author: gemini!!!
"""
import idaapi
import idc
import idautils
import ida_search
import ida_bytes
import ida_funcs


def get_string_address(target_str):
    print(f"[*] [Step 1] 搜索字符串 \"{target_str}\" ...")
    for s in idautils.Strings():
        if str(s) == target_str:
            print(f"    [+] 找到字符串地址: {hex(s.ea)}")
            return s.ea
    print("    [!] 未找到字符串")
    return None


def find_real_target_function(string_ea):
    print(f"[*] [Step 2] 追踪：字符串 -> 全局变量 -> 目标函数...")

    # 1. 找到引用字符串的代码位置 (初始化位置)
    string_refs = list(idautils.DataRefsTo(string_ea))
    global_var_ea = None

    for ref in string_refs:
        seg = idaapi.getseg(ref)
        if seg and seg.type == idaapi.SEG_CODE:
            print(f"    [+] 找到字符串引用代码: {hex(ref)}")
            # 2. 在引用处附近寻找全局变量 (LEA RCX, Global)
            # 这里的逻辑是：C++构造函数通常是 Constructor(GlobalVar, String)
            # 所以 String 是 RDX，GlobalVar 是 RCX
            # 我们在该指令前后找 LEA RCX, [MEM]

            # 搜索范围：前后 5 条指令
            start_search = ref - 20
            end_search = ref + 20

            curr = start_search
            while curr < end_search:
                mnem = idc.print_insn_mnem(curr).lower()
                op0 = idc.print_operand(curr, 0).lower()

                if mnem == "lea" and "rcx" in op0:
                    # 获取第二个操作数的值（即全局变量地址）
                    possible_global = idc.get_operand_value(curr, 1)
                    # 简单验证一下这个地址是不是在数据段
                    g_seg = idaapi.getseg(possible_global)
                    if g_seg and g_seg.type != idaapi.SEG_CODE:
                        global_var_ea = possible_global
                        print(f"    [+] 反推成功！锁定全局变量地址: {hex(global_var_ea)}")
                        break
                curr = idc.next_head(curr)

            if global_var_ea: break

    if not global_var_ea:
        print("    [!] 无法定位全局变量，脚本终止。")
        return None

    # 3. 找谁引用了这个全局变量 (并且是 LEA RDX, Global)
    # 这就是我们要找的 setCipherKey
    g_refs = list(idautils.DataRefsTo(global_var_ea))
    for gr in g_refs:
        # 跳过初始化函数本身 (通过地址距离或者指令类型判断)
        # 简单判断：目标应该是 LEA RDX, [Global]，而不是 LEA RCX
        mnem = idc.print_insn_mnem(gr).lower()
        op0 = idc.print_operand(gr, 0).lower()

        if mnem == "lea" and "rdx" in op0:
            print(f"    [+] 找到关键引用 (LEA RDX): {hex(gr)}")
            func = idaapi.get_func(gr)
            if func:
                print(f"    [+] 锁定最终目标函数: {hex(func.start_ea)}")
                return func.start_ea

    print("    [!] 未找到符合 LEA RDX, Global 的引用。")
    return None


def find_hook_point_in_func(func_start):
    print(f"[*] [Step 3] 在函数 {hex(func_start)} 中寻找 Hook 点 (Magic -2)...")
    func = idaapi.get_func(func_start)
    if not func: return None

    # 扫描 Magic Number -2 (0xFFFFFFFFFFFFFFFE)
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        op1_val = idc.get_operand_value(ea, 1)
        # 处理有符号数和无符号数表示
        if op1_val == 0xFFFFFFFFFFFFFFFE or op1_val == -2:
            # 找到了 mov [rbp+xx], -2
            # 往上找最近的 lea rbp, [rsp+xx]
            prev = ea
            for _ in range(10):  # 回溯范围稍大一点
                prev = idc.prev_head(prev)
                mnem = idc.print_insn_mnem(prev).lower()
                op0 = idc.print_operand(prev, 0).lower()

                if mnem == "lea" and "rbp" in op0:
                    print(f"    [+] 找到最佳 Hook 点: {hex(prev)}")
                    print(f"        指令: {idc.generate_disasm_line(prev, 0)}")
                    return prev

    print("    [!] 未找到 Magic Number，尝试直接使用函数头作为备选...")
    return func_start


def check_unique(pattern):
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    first = ida_search.find_binary(min_ea, max_ea, pattern, 16, idc.SEARCH_DOWN)
    if first == idc.BADADDR: return False
    second = ida_search.find_binary(first + 1, max_ea, pattern, 16, idc.SEARCH_DOWN)
    return second == idc.BADADDR


def generate_sig(start_ea):
    print(f"[*] [Step 4] 生成唯一特征码 (起始: {hex(start_ea)})...")
    current_ea = start_ea
    sig_parts = []

    while True:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, current_ea)
        if length == 0: break

        raw = list(idc.get_bytes(current_ea, length))
        mask = ["x"] * length

        # 智能处理 E8(CALL) / E9(JMP) 后面的偏移
        if raw[0] in [0xE8, 0xE9]:
            for i in range(1, length): mask[i] = "?"

        # 智能处理 LEA RBP, [RSP+XX] 的偏移，防止栈大小变化导致特征失效
        # 指令通常是: 48 8D 6C 24 XX
        if raw[0] == 0x48 and raw[1] == 0x8D and raw[2] == 0x6C and raw[3] == 0x24:
            mask[4] = "?"  # 通配偏移量

        # 处理 Magic Number 指令中的偏移
        # mov [rbp+XX], -2
        if raw[0] == 0x48 and raw[1] == 0xC7 and raw[2] == 0x45:
            mask[3] = "?"  # 通配 [rbp+XX] 中的 XX

        curr_sig = []
        for b, m in zip(raw, mask):
            curr_sig.append(f"{b:02X}" if m == "x" else "?")

        sig_parts.extend(curr_sig)
        current_pattern = " ".join(sig_parts)

        if check_unique(current_pattern):
            print(f"    [+] 特征码生成完毕! (长度: {len(sig_parts)} bytes)")
            return current_pattern, sig_parts, "".join(mask)

        if len(sig_parts) > 200:
            print("    [!] 特征码过长，停止。")
            return None, None, None

        current_ea += length


def main():
    print("\n" + "=" * 60)
    print("   WeChat DB Key Finder v2.0 (Smart Jump Mode)")
    print("=" * 60)

    # 1. 找字符串
    str_addr = get_string_address("com.Tencent.WCDB.Config.Cipher")
    if not str_addr: return

    # 2. 找真正的目标函数 (二级跳)
    target_func = find_real_target_function(str_addr)
    if not target_func: return

    # 3. 找函数内部 Hook 点
    hook_ea = find_hook_point_in_func(target_func)
    if not hook_ea: hook_ea = target_func  # Fallback

    # 4. 生成特征
    pat, bytes_list, mask_str = generate_sig(hook_ea)

    if pat:
        print("\n" + "=" * 20 + " FINAL RESULT " + "=" * 20)
        print(f"[Hook Address]: {hex(hook_ea)}")
        print(f"[IDA Pattern] : {pat}")

        c_bytes = ", ".join([("0x" + b) if b != "?" else "0x00" for b in bytes_list])
        print(f"[C++ Bytes]   : {{ {c_bytes} }}")

        # 转换 mask 格式为 x/?
        final_mask = "".join(["x" if b != "?" else "?" for b in bytes_list])
        print(f"[Mask]        : \"{final_mask}\"")
        print("=" * 54)


if __name__ == "__main__":
    main()