declare module '@deepiri/shared-utils' {
  export function createLogger(name?: string): { error: (...args: any[]) => void; warn: (...args: any[]) => void; info: (...args: any[]) => void; debug: (...args: any[]) => void };
  export function someOtherExport(...args: any[]): any;
}
