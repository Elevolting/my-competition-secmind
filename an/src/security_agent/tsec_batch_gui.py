"""Small desktop front end for the same tested batch operations."""
from __future__ import annotations

import asyncio
import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from security_agent.tsec_batch import BatchOperator, make_client


class BatchWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.client = make_client(Path('.env'))
        self.operator = BatchOperator(self.client)
        self.events = queue.Queue()
        self.busy = False
        self.last_result = None
        root.title('TSec 题目批量工具')
        root.geometry('1120x820')
        frame = ttk.Frame(root, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='TSec 题目批量工具', font=('Microsoft YaHei UI', 18, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Ctrl / Shift 多选题目。最多同时启动 3 道题；答案由下方 JSON 提交。').pack(
            anchor='w', pady=8)
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill='x', pady=6)
        self.buttons = []
        for label, command in [('刷新题目', self.refresh), ('启动所选', self.start), ('关闭所选', self.close),
                               ('导出结果', self.export)]:
            button = ttk.Button(toolbar, text=label, command=command)
            button.pack(side='left', padx=(0, 8))
            self.buttons.append(button)
        self.state = tk.StringVar(value='就绪')
        ttk.Label(toolbar, textvariable=self.state).pack(side='left')
        table = ttk.Frame(frame)
        table.pack(fill='both', expand=True)
        columns = ('code', 'description', 'difficulty', 'progress', 'status', 'addresses')
        self.tree = ttk.Treeview(table, columns=columns, show='headings', selectmode='extended', height=10)
        for name, label, width in zip(columns, ('题目', '描述', '难度', 'Flag 进度', '容器状态', '入口地址'),
                                      (80, 320, 65, 80, 100, 290), strict=True):
            self.tree.heading(name, text=label)
            self.tree.column(name, width=width, minwidth=50)
        scrollbar = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        ttk.Label(frame, text='批量答案 JSON（同一题多个 Flag 用数组）').pack(anchor='w', pady=(12, 4))
        self.answers = tk.Text(frame, height=7, undo=True, font=('Consolas', 11))
        self.answers.pack(fill='x')
        self.answers.insert('1.0', '{}')
        actions = ttk.Frame(frame)
        actions.pack(fill='x', pady=8)
        for label, command in [('导入 JSON', self.load), ('批量提交 Flag', self.submit)]:
            button = ttk.Button(actions, text=label, command=command)
            button.pack(side='left', padx=(0, 8))
            self.buttons.append(button)
        self.auto_close = tk.BooleanVar(value=False)
        ttk.Checkbutton(actions, text='提交后关闭已全部通关的题目', variable=self.auto_close).pack(side='left')
        ttk.Label(frame, text='本次结果（正确性、得分和进度以平台回执为准）').pack(anchor='w')
        self.output = tk.Text(frame, height=11, state='disabled', font=('Consolas', 10))
        self.output.pack(fill='both', expand=True, pady=4)
        root.protocol('WM_DELETE_WINDOW', self.quit)
        root.after(100, self.poll)
        self.refresh()

    def run(self, operation, label, *, refresh=True):
        if self.busy:
            return
        self.busy = True
        self.state.set(label + '…')
        for button in self.buttons:
            button.configure(state='disabled')

        def work():
            async def execute():
                result = await operation()
                try:
                    items = await self.client.list_challenges() if refresh else result
                    warning = None
                except Exception as exc:
                    items, warning = None, f'操作结果已保留，刷新失败：{exc}'
                return result, items, warning
            try:
                self.events.put(('ok', asyncio.run(execute())))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            kind, data = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            for button in self.buttons:
                button.configure(state='normal')
            if kind == 'error':
                self.state.set('操作失败')
                self.last_result = {'error': data}
                self.show(self.last_result)
                messagebox.showerror('操作失败', data)
            else:
                result, items, warning = data
                self.last_result = result
                self.show(result)
                self.state.set(warning or '操作已返回，请查看下方逐项结果')
                if items is not None:
                    selected = set(self.tree.selection())
                    self.tree.delete(*self.tree.get_children())
                    for item in items:
                        code = item['unique_code']
                        self.tree.insert('', 'end', iid=code, values=(code, item.get('description'),
                            item.get('difficulty'), f"{item.get('correct_flag_count', 0)}/{item.get('flag_count', 0)}",
                            item.get('container_status'), ', '.join(item.get('container_addr', []))))
                    self.tree.selection_set([code for code in selected if self.tree.exists(code)])
        self.root.after(100, self.poll)

    def show(self, data):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', json.dumps(data, ensure_ascii=False, indent=2))
        self.output.configure(state='disabled')

    def refresh(self):
        self.run(self.client.list_challenges, '刷新题目', refresh=False)

    def start(self):
        codes = list(self.tree.selection())
        self.run(lambda: self.operator.start(codes), '启动所选题目')

    def close(self):
        codes = list(self.tree.selection())
        if codes and messagebox.askyesno('关闭容器', '关闭以下题目会中断正在进行的解题：\n' + ', '.join(codes)):
            self.run(lambda: self.operator.close(codes), '关闭所选题目')

    def submit(self):
        text, close = self.answers.get('1.0', 'end-1c'), self.auto_close.get()
        self.run(lambda: self.operator.submit(text, close_completed=close), '提交 Flag')

    def load(self):
        path = filedialog.askopenfilename(filetypes=[('JSON 答案文件', '*.json')])
        if path:
            try:
                text = Path(path).read_text(encoding='utf-8-sig')
                self.answers.delete('1.0', 'end')
                self.answers.insert('1.0', text)
            except (OSError, UnicodeError) as exc:
                messagebox.showerror('读取失败', str(exc))

    def export(self):
        if self.last_result is None:
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', initialfile='tsec-results.json')
        if path:
            try:
                Path(path).write_text(json.dumps(self.last_result, ensure_ascii=False, indent=2), encoding='utf-8')
            except OSError as exc:
                messagebox.showerror('保存失败', str(exc))

    def quit(self):
        if self.busy:
            messagebox.showinfo('操作进行中', '请等待当前批次返回结果后再退出。')
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    BatchWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
