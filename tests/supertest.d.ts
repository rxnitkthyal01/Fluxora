declare module 'supertest' {
  interface Test extends Promise<{body:any;headers:Record<string,string>;status:number}> {
    send(value:unknown):Test;
    set(name:string,value:string):Test;
    expect(status:number):Test;
    expect(callback:(response:{body:any;headers:Record<string,string>;status:number})=>void):Test;
  }
  const request:(app:unknown)=>{get(path:string):Test;post(path:string):Test;put(path:string):Test;delete(path:string):Test};
  export default request;
}
