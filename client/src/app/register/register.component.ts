import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';
import { User } from '../_models/User';
import { AccountService } from '../_services/account.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
@Output() cancelRegister= new EventEmitter();

model:any={};

  constructor(private accountService:AccountService) { }
  

  ngOnInit(): void {
  }
  Register(){
    this.accountService.register(this.model).subscribe(response=>{
      console.log(response);
      this.Cancel();
    },error=>{
      console.log(error);  
    })
    console.log("Register");
  }
  
  Cancel(){
    this.cancelRegister.emit(false);
    console.log("cancel");
  }

}