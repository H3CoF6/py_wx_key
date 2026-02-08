"""
IDA 脚本：生成适配 InitializeContext 的 Pattern, Mask 和 Offset
逻辑：
  Pattern/Mask -> 定位函数头部 (func_start)
  Offset       -> func_start 到内部 Hook 点的距离
author: Gemini
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
    string_refs = list(idautils.DataRefsTo(string_ea))
    global_var_ea = None

    # 1. 找全局变量
    for ref in string_refs:
        seg = idaapi.getseg(ref)
        if seg and seg.type == idaapi.SEG_CODE:
            start_search = ref - 20
            end_search = ref + 20
            curr = start_search
            while curr < end_search:
                mnem = idc.print_insn_mnem(curr).lower()
                op0 = idc.print_operand(curr, 0).lower()
                if mnem == "lea" and "rcx" in op0:
                    possible_global = idc.get_operand_value(curr, 1)
                    g_seg = idaapi.getseg(possible_global)
                    if g_seg and g_seg.type != idaapi.SEG_CODE:
                        global_var_ea = possible_global
                        print(f"    [+] 锁定全局变量: {hex(global_var_ea)}")
                        break
                curr = idc.next_head(curr)
            if global_var_ea: break

    if not global_var_ea:
        print("    [!] 无法定位全局变量")
        return None

    # 2. 找目标函数 (引用该全局变量的函数)
    g_refs = list(idautils.DataRefsTo(global_var_ea))
    for gr in g_refs:
        mnem = idc.print_insn_mnem(gr).lower()
        op0 = idc.print_operand(gr, 0).lower()
        # 寻找 LEA RDX, [Global]
        if mnem == "lea" and "rdx" in op0:
            func = idaapi.get_func(gr)
            if func:
                print(f"    [+] 锁定目标函数入口 (Pattern起始点): {hex(func.start_ea)}")
                return func.start_ea
    return None


def find_hook_point_in_func(func_start):
    print(f"[*] [Step 3] 在函数内部寻找 Hook 点 (Magic -2)...")
    func = idaapi.get_func(func_start)
    if not func: return None

    # 扫描 Magic Number -2
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        op1_val = idc.get_operand_value(ea, 1)
        if op1_val == 0xFFFFFFFFFFFFFFFE or op1_val == -2:
            # 找到 mov [rbp+xx], -2，回溯找 lea rbp
            prev = ea
            for _ in range(10):
                prev = idc.prev_head(prev)
                mnem = idc.print_insn_mnem(prev).lower()
                op0 = idc.print_operand(prev, 0).lower()
                if mnem == "lea" and "rbp" in op0:
                    print(f"    [+] 找到 Hook 点 (Target): {hex(prev)}")
                    return prev

    print("    [!] 未找到 Magic Number，Hook 点默认为函数入口")
    return func_start


def check_unique(pattern):
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    first = ida_search.find_binary(min_ea, max_ea, pattern, 16, idc.SEARCH_DOWN)
    if first == idc.BADADDR: return False
    second = ida_search.find_binary(first + 1, max_ea, pattern, 16, idc.SEARCH_DOWN)
    return second == idc.BADADDR


def generate_sig(start_ea):
    print(f"[*] [Step 4] 为函数入口 {hex(start_ea)} 生成唯一特征码...")
    current_ea = start_ea
    sig_parts = []

    while True:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, current_ea)
        if length == 0: break

        raw = list(idc.get_bytes(current_ea, length))
        mask = ["x"] * length

        # 这里的模糊匹配规则可以根据需要增减
        if raw[0] in [0xE8, 0xE9]:  # CALL/JMP
            for i in range(1, length): mask[i] = "?"

        # 48 8D 6C 24 XX -> lea rbp, [rsp+xx] (栈帧偏移可能变)
        if len(raw) >= 5 and raw[0] == 0x48 and raw[1] == 0x8D and raw[2] == 0x6C and raw[3] == 0x24:
            mask[4] = "?"

        curr_sig = []
        for b, m in zip(raw, mask):
            curr_sig.append(f"{b:02X}" if m == "x" else "?")
        sig_parts.extend(curr_sig)

        current_pattern = " ".join(sig_parts)
        if check_unique(current_pattern):
            return current_pattern, sig_parts, "".join(mask)

        if len(sig_parts) > 256:
            print("    [!] 特征码太长了，生成失败")
            return None, None, None

        current_ea += length


def main():
    print("\n" + "=" * 60)
    print("   WeChat DB Key Param Generator")
    print("=" * 60)

    # 1. 找函数入口 (作为 Pattern 的基准)
    str_addr = get_string_address("com.Tencent.WCDB.Config.Cipher")
    if not str_addr: return

    func_start = find_real_target_function(str_addr)
    if not func_start: return

    # 2. 找内部 Hook 点 (Target)
    hook_ea = find_hook_point_in_func(func_start)
    if not hook_ea: hook_ea = func_start

    # 3. 计算 offset
    # C++代码: target = result[0] + offset
    # 所以: offset = hook_ea - func_start
    offset = hook_ea - func_start

    # 4. 生成函数头的特征码
    pat, bytes_list, mask_str = generate_sig(func_start)

    if pat:
        print("\n" + "=" * 20 + " 复制以下内容到 Python/C++ " + "=" * 20)

        # 1. Pattern (用于 pattern 参数)
        print(f"pattern = \"{pat}\"")

        # 2. Mask (用于 mask 参数)
        # 将 x/? 格式转换为 C++ 易读格式
        final_mask = "".join(["x" if b != "?" else "?" for b in bytes_list])
        print(f"mask    = \"{final_mask}\"")

        # 3. Offset (用于 offset 参数) !!! 这里就是你要的 !!!
        print(f"offset  = {offset}  (0x{offset:X})")

        print("-" * 60)
        print(f"[Debug info]")
        print(f"Function Start : {hex(func_start)}")
        print(f"Hook Address   : {hex(hook_ea)}")
        print("=" * 60)


if __name__ == "__main__":
    main()